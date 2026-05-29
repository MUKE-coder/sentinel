// Package postgres provides a PostgreSQL storage adapter for Sentinel.
//
// The implementation reuses the GORM-based store from storage/sqlite —
// the schema, queries, and behaviour are identical across SQLite and
// Postgres because they all run through GORM with dialect-agnostic models.
// Only the underlying driver and connection-pool tuning differ.
package postgres

import (
	"fmt"

	"github.com/MUKE-coder/sentinel/storage/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Options configures the Postgres adapter beyond the DSN.
type Options struct {
	// MaxOpenConns sets the maximum number of open connections to the database.
	// Default: 25.
	MaxOpenConns int
	// MaxIdleConns sets the maximum number of idle connections in the pool.
	// Default: 5.
	MaxIdleConns int
}

// New opens a Postgres connection at dsn (any DSN string GORM/lib-pq accepts —
// "host=... user=... dbname=... sslmode=..." or "postgres://user:pass@host/db")
// and returns a Sentinel store ready for use. Schema migrations are NOT run
// here — call store.Migrate(ctx) after construction.
func New(dsn string, opts ...Options) (*sqlite.Store, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres: empty DSN")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("postgres: get sql.DB: %w", err)
	}

	maxOpen, maxIdle := 25, 5
	if len(opts) > 0 {
		if opts[0].MaxOpenConns > 0 {
			maxOpen = opts[0].MaxOpenConns
		}
		if opts[0].MaxIdleConns > 0 {
			maxIdle = opts[0].MaxIdleConns
		}
	}
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)

	return sqlite.NewFromGormDB(db), nil
}
