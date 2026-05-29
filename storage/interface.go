// Package storage defines the storage interface for Sentinel.
// Implementations include in-memory (dev/test), SQLite (default),
// and PostgreSQL (production).
package storage

// Store is the union of every storage capability Sentinel needs.
// It composes focused sub-interfaces (ThreatStore, ActorStore, IPStore,
// AuditStore, MetricStore, UserActivityStore, AnalyticsStore, ScoreStore,
// LifecycleStore) so callers that need only one capability can depend on
// just that sub-interface — e.g. a Redis-backed IPStore can be swapped in
// without re-implementing the whole world. Existing implementations
// (memory, sqlite, postgres) keep working unchanged because Store is the
// same surface area as before.
type Store interface {
	ThreatStore
	ActorStore
	IPStore
	AuditStore
	MetricStore
	UserActivityStore
	AnalyticsStore
	ScoreStore
	LifecycleStore
}
