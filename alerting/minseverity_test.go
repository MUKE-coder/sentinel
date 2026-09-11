package alerting

import (
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func TestDispatcher_MinSeverityChangesWhileRunning(t *testing.T) {
	d := NewDispatcher(sentinel.AlertConfig{MinSeverity: sentinel.SeverityHigh})
	if d.meetsSeverityThreshold(sentinel.SeverityMedium) {
		t.Fatal("Medium must not alert under a High threshold")
	}
	d.SetMinSeverity(sentinel.SeverityLow)
	if !d.meetsSeverityThreshold(sentinel.SeverityMedium) {
		t.Error("after lowering the threshold to Low, Medium must alert")
	}
	if d.MinSeverity() != sentinel.SeverityLow {
		t.Errorf("MinSeverity() = %s, want Low", d.MinSeverity())
	}
}
