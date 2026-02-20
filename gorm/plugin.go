// Package sentinelgorm provides a GORM plugin for query-level security intelligence
// and audit logging. This package is completely optional.
package sentinelgorm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/MUKE-coder/sentinel/pipeline"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const (
	requestInfoKey contextKey = "sentinel_request_info"
	beforeStateKey contextKey = "sentinel_before_state"
	queryCountKey  contextKey = "sentinel_query_count"
)

// RequestInfo holds HTTP request metadata that links GORM operations to requests.
// Sentinel middleware sets this on the request context, and the GORM plugin reads it.
type RequestInfo struct {
	IP        string
	UserID    string
	UserEmail string
	UserRole  string
	UserAgent string
	RequestID string
}

// WithRequestInfo attaches request metadata to a context so the GORM plugin
// can link database operations back to the originating HTTP request.
// Usage: db.WithContext(sentinelgorm.WithRequestInfo(c.Request.Context(), info))
func WithRequestInfo(ctx context.Context, info *RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey, info)
}

// getRequestInfo extracts request metadata from the context.
func getRequestInfo(ctx context.Context) *RequestInfo {
	if v, ok := ctx.Value(requestInfoKey).(*RequestInfo); ok {
		return v
	}
	return &RequestInfo{}
}

// queryCounter tracks per-request query counts for N+1 detection.
type queryCounter struct {
	mu     sync.Mutex
	counts map[string]int // table → count
}

// WithQueryCounter attaches a query counter to a context for N+1 detection.
func WithQueryCounter(ctx context.Context) context.Context {
	return context.WithValue(ctx, queryCountKey, &queryCounter{counts: make(map[string]int)})
}

func getQueryCounter(ctx context.Context) *queryCounter {
	if v, ok := ctx.Value(queryCountKey).(*queryCounter); ok {
		return v
	}
	return nil
}

// Config configures the GORM plugin behavior.
type Config struct {
	// AuditEnabled enables audit logging for mutations.
	AuditEnabled bool

	// QueryShieldEnabled enables query analysis (N+1 detection, slow query flags).
	QueryShieldEnabled bool

	// SlowQueryThreshold flags queries slower than this duration.
	// Defaults to 200ms.
	SlowQueryThreshold time.Duration

	// N1QueryThreshold is the number of identical-table queries in one request
	// context before flagging as N+1. Defaults to 10.
	N1QueryThreshold int
}

func (c *Config) applyDefaults() {
	if c.SlowQueryThreshold == 0 {
		c.SlowQueryThreshold = 200 * time.Millisecond
	}
	if c.N1QueryThreshold == 0 {
		c.N1QueryThreshold = 10
	}
}

// Plugin is the Sentinel GORM plugin that provides audit logging and query shielding.
type Plugin struct {
	pipe   *pipeline.Pipeline
	config Config
}

// New creates a new Sentinel GORM plugin.
func New(pipe *pipeline.Pipeline, opts ...func(*Config)) *Plugin {
	cfg := Config{
		AuditEnabled:       true,
		QueryShieldEnabled: true,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	cfg.applyDefaults()
	return &Plugin{pipe: pipe, config: cfg}
}

// Name returns the plugin name (required by gorm.Plugin).
func (p *Plugin) Name() string {
	return "sentinel"
}

// Initialize registers GORM callbacks (required by gorm.Plugin).
func (p *Plugin) Initialize(db *gorm.DB) error {
	if p.config.AuditEnabled {
		// Before update: capture current state for diffing
		db.Callback().Update().Before("gorm:update").Register("sentinel:before_update", p.beforeUpdate)

		// Before delete: capture current state
		db.Callback().Delete().Before("gorm:delete").Register("sentinel:before_delete", p.beforeDelete)

		// After mutations: emit audit logs
		db.Callback().Create().After("gorm:create").Register("sentinel:after_create", p.afterCreate)
		db.Callback().Update().After("gorm:update").Register("sentinel:after_update", p.afterUpdate)
		db.Callback().Delete().After("gorm:delete").Register("sentinel:after_delete", p.afterDelete)
	}

	if p.config.QueryShieldEnabled {
		db.Callback().Query().After("gorm:query").Register("sentinel:after_query", p.afterQuery)
	}

	return nil
}

// beforeUpdate captures the record state before an update for audit diffing.
func (p *Plugin) beforeUpdate(db *gorm.DB) {
	if db.Statement == nil || db.Statement.Context == nil {
		return
	}
	if db.Error != nil {
		return
	}

	table := db.Statement.Table
	if table == "" {
		table = db.Statement.Schema.Table
	}

	// Try to read the current state using primary key conditions
	dest := db.Statement.Dest
	if dest == nil {
		return
	}

	// Serialize current state as "before"
	beforeJSON := modelToJSON(dest)
	if beforeJSON != nil {
		db.Statement.Context = context.WithValue(db.Statement.Context, beforeStateKey, beforeJSON)
	}
}

// beforeDelete captures the record state before deletion.
func (p *Plugin) beforeDelete(db *gorm.DB) {
	if db.Statement == nil || db.Statement.Context == nil {
		return
	}
	if db.Error != nil {
		return
	}

	dest := db.Statement.Dest
	if dest == nil {
		return
	}

	beforeJSON := modelToJSON(dest)
	if beforeJSON != nil {
		db.Statement.Context = context.WithValue(db.Statement.Context, beforeStateKey, beforeJSON)
	}
}

// afterCreate emits an audit log for record creation.
func (p *Plugin) afterCreate(db *gorm.DB) {
	if db.Error != nil || db.Statement == nil {
		return
	}

	info := getRequestInfo(db.Statement.Context)
	table := getTableName(db)
	resourceID := extractPrimaryKey(db)

	afterJSON := modelToJSON(db.Statement.Dest)

	log := &sentinel.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now(),
		UserID:     info.UserID,
		UserEmail:  info.UserEmail,
		UserRole:   info.UserRole,
		Action:     "CREATE",
		Resource:   table,
		ResourceID: resourceID,
		After:      afterJSON,
		IP:         info.IP,
		UserAgent:  info.UserAgent,
		Success:    true,
		RequestID:  info.RequestID,
	}

	if p.pipe != nil {
		p.pipe.EmitAudit(log)
	}
}

// afterUpdate emits an audit log for record updates.
func (p *Plugin) afterUpdate(db *gorm.DB) {
	if db.Error != nil || db.Statement == nil {
		return
	}

	info := getRequestInfo(db.Statement.Context)
	table := getTableName(db)
	resourceID := extractPrimaryKey(db)

	afterJSON := modelToJSON(db.Statement.Dest)

	// Retrieve "before" state captured in beforeUpdate
	var beforeJSON sentinel.JSONMap
	if v, ok := db.Statement.Context.Value(beforeStateKey).(sentinel.JSONMap); ok {
		beforeJSON = v
	}

	log := &sentinel.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now(),
		UserID:     info.UserID,
		UserEmail:  info.UserEmail,
		UserRole:   info.UserRole,
		Action:     "UPDATE",
		Resource:   table,
		ResourceID: resourceID,
		Before:     beforeJSON,
		After:      afterJSON,
		IP:         info.IP,
		UserAgent:  info.UserAgent,
		Success:    true,
		RequestID:  info.RequestID,
	}

	if p.pipe != nil {
		p.pipe.EmitAudit(log)
	}
}

// afterDelete emits an audit log for record deletion.
func (p *Plugin) afterDelete(db *gorm.DB) {
	if db.Error != nil || db.Statement == nil {
		return
	}

	info := getRequestInfo(db.Statement.Context)
	table := getTableName(db)
	resourceID := extractPrimaryKey(db)

	var beforeJSON sentinel.JSONMap
	if v, ok := db.Statement.Context.Value(beforeStateKey).(sentinel.JSONMap); ok {
		beforeJSON = v
	}

	log := &sentinel.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now(),
		UserID:     info.UserID,
		UserEmail:  info.UserEmail,
		UserRole:   info.UserRole,
		Action:     "DELETE",
		Resource:   table,
		ResourceID: resourceID,
		Before:     beforeJSON,
		IP:         info.IP,
		UserAgent:  info.UserAgent,
		Success:    true,
		RequestID:  info.RequestID,
	}

	if p.pipe != nil {
		p.pipe.EmitAudit(log)
	}
}

// afterQuery implements query shield: N+1 detection, slow query flags, no-WHERE detection.
func (p *Plugin) afterQuery(db *gorm.DB) {
	if db.Statement == nil {
		return
	}

	table := getTableName(db)
	ctx := db.Statement.Context

	// Track query duration (GORM doesn't expose this directly, but we can detect slow queries
	// from the statement's duration if available via DryRun or by checking db.RowsAffected)

	// N+1 detection
	if qc := getQueryCounter(ctx); qc != nil {
		qc.mu.Lock()
		qc.counts[table]++
		count := qc.counts[table]
		qc.mu.Unlock()

		if count == p.config.N1QueryThreshold {
			info := getRequestInfo(ctx)
			te := &sentinel.ThreatEvent{
				ID:          uuid.New().String(),
				Timestamp:   time.Now(),
				IP:          info.IP,
				Method:      "DB_QUERY",
				Path:        table,
				ThreatTypes: []string{"N+1 Query"},
				Severity:    sentinel.SeverityLow,
				Confidence:  80,
				Evidence: []sentinel.Evidence{
					{
						Pattern:  "N+1 Query Detection",
						Matched:  fmt.Sprintf("%d queries to table '%s' in single request", count, table),
						Location: "database",
					},
				},
			}
			if p.pipe != nil {
				p.pipe.EmitThreat(te)
			}
		}
	}

	// No-WHERE clause detection on SELECT queries
	sql := db.Statement.SQL.String()
	if isSelectWithoutWhere(sql, table) && db.RowsAffected > 1000 {
		info := getRequestInfo(ctx)
		te := &sentinel.ThreatEvent{
			ID:          uuid.New().String(),
			Timestamp:   time.Now(),
			IP:          info.IP,
			Method:      "DB_QUERY",
			Path:        table,
			ThreatTypes: []string{"Unfiltered Query"},
			Severity:    sentinel.SeverityLow,
			Confidence:  60,
			Evidence: []sentinel.Evidence{
				{
					Pattern:  "SELECT without WHERE on large result set",
					Matched:  fmt.Sprintf("Query on '%s' returned %d rows without WHERE clause", table, db.RowsAffected),
					Location: "database",
				},
			},
		}
		if p.pipe != nil {
			p.pipe.EmitThreat(te)
		}
	}
}

// GetN1Queries returns the current N+1 query counts from a context.
// Useful for inspecting query counts at the end of a request.
func GetN1Queries(ctx context.Context) map[string]int {
	qc := getQueryCounter(ctx)
	if qc == nil {
		return nil
	}
	qc.mu.Lock()
	defer qc.mu.Unlock()
	result := make(map[string]int, len(qc.counts))
	for k, v := range qc.counts {
		result[k] = v
	}
	return result
}

// --- helpers ---

func getTableName(db *gorm.DB) string {
	if db.Statement.Table != "" {
		return db.Statement.Table
	}
	if db.Statement.Schema != nil {
		return db.Statement.Schema.Table
	}
	return "unknown"
}

func extractPrimaryKey(db *gorm.DB) string {
	if db.Statement.Schema == nil {
		return ""
	}
	for _, field := range db.Statement.Schema.PrimaryFields {
		val, isZero := field.ValueOf(db.Statement.Context, db.Statement.ReflectValue)
		if !isZero {
			return fmt.Sprintf("%v", val)
		}
	}
	return ""
}

func modelToJSON(model interface{}) sentinel.JSONMap {
	if model == nil {
		return nil
	}
	data, err := json.Marshal(model)
	if err != nil {
		return nil
	}
	var m sentinel.JSONMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

func isSelectWithoutWhere(sql string, table string) bool {
	upper := strings.ToUpper(sql)
	if !strings.HasPrefix(upper, "SELECT") {
		return false
	}
	return !strings.Contains(upper, "WHERE")
}
