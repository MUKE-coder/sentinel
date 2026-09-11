package middleware

import (
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/MUKE-coder/sentinel/v2/countertest"
)

func TestMemoryCounterStoreConformance(t *testing.T) {
	countertest.Run(t, func(t *testing.T) sentinel.CounterStore {
		s := NewMemoryCounterStore()
		t.Cleanup(s.Close)
		return s
	})
}
