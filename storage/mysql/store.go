// Package mysql provides a MySQL storage adapter for Sentinel.
//
// The implementation reuses the GORM-based store from storage/sqlite — the
// schema, queries, and behaviour are identical across SQLite, Postgres, and
// MySQL because they all run through GORM with dialect-agnostic models. Only
// the driver and connection-pool tuning differ.
//
// MySQL needs one thing the others don't: a bound on how wide an untyped
// string column is, because an unbounded one becomes LONGTEXT and MySQL
// cannot index that. DefaultStringSize gives every untagged string column a
// VARCHAR, and the columns that hold paths, user agents, and JSON blobs are
// tagged type:text in the shared models.
package mysql

import (
	"fmt"

	"github.com/MUKE-coder/sentinel/v2/storage/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// defaultStringSize bounds untagged string columns. 256 keeps every index
// well inside MySQL's 3072-byte limit, even on utf8mb4 (4 bytes a
// character).
const defaultStringSize = 256

// datetimePrecision is the fractional-second precision for every timestamp
// column. The driver's default is datetime(3), which silently truncates to
// milliseconds — and the audit log's hash chain covers the timestamp to the
// microsecond, so a chain written to MySQL would fail its own verification.
const datetimePrecision = 6

// Options configures the MySQL adapter beyond the DSN.
type Options struct {
	// MaxOpenConns sets the maximum number of open connections to the
	// database. Default: 25.
	MaxOpenConns int
	// MaxIdleConns sets the maximum number of idle connections in the pool.
	// Default: 5.
	MaxIdleConns int
}

// New opens a MySQL connection at dsn and returns a Sentinel store ready for
// use. dsn is a go-sql-driver DSN:
//
//	user:password@tcp(127.0.0.1:3306)/sentinel?charset=utf8mb4&parseTime=True&loc=Local
//
// parseTime=True is required — Sentinel stores timestamps, and without it the
// driver hands back []byte instead of time.Time. Schema migrations are NOT
// run here; call store.Migrate(ctx) after construction, as Mount does.
func New(dsn string, opts ...Options) (*sqlite.Store, error) {
	if dsn == "" {
		return nil, fmt.Errorf("mysql: empty DSN")
	}

	precision := datetimePrecision
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                      dsn,
		DefaultStringSize:        defaultStringSize,
		DefaultDatetimePrecision: &precision,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("mysql: open: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("mysql: get sql.DB: %w", err)
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
