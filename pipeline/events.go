// Package pipeline provides the async event pipeline for Sentinel.
// All security events flow through this pipeline, ensuring middleware
// never blocks waiting for storage or external calls.
package pipeline

import (
	"time"
)

// EventType identifies the kind of event flowing through the pipeline.
type EventType string

const (
	// EventThreat is a detected security threat.
	EventThreat EventType = "threat"

	// EventUserActivity is a user activity record.
	EventUserActivity EventType = "user_activity"

	// EventPerformance is a performance measurement.
	EventPerformance EventType = "performance"

	// EventAudit is an audit log entry.
	EventAudit EventType = "audit"
)

// Event is the envelope for all events flowing through the pipeline.
type Event struct {
	// Type identifies what kind of event this is.
	Type EventType `json:"type"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Payload is the event data. The concrete type depends on Type.
	Payload interface{} `json:"payload"`
}
