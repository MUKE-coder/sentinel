package pipeline

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewPipeline(t *testing.T) {
	p := New(0)
	if p == nil {
		t.Fatal("expected non-nil pipeline")
	}
	if cap(p.events) != DefaultBufferSize {
		t.Errorf("expected buffer capacity %d, got %d", DefaultBufferSize, cap(p.events))
	}

	p2 := New(500)
	if cap(p2.events) != 500 {
		t.Errorf("expected buffer capacity 500, got %d", cap(p2.events))
	}
}

func TestEmitAndHandle(t *testing.T) {
	p := New(100)
	var received atomic.Int64

	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		received.Add(1)
		return nil
	}))

	p.Start(2)

	for i := 0; i < 50; i++ {
		p.Emit(Event{
			Type:    EventThreat,
			Payload: i,
		})
	}

	p.Stop()

	if received.Load() != 50 {
		t.Errorf("expected 50 events handled, got %d", received.Load())
	}
}

func TestEmitNonBlocking(t *testing.T) {
	// Use a very small buffer
	p := New(5)
	// Don't start workers — buffer should fill up

	for i := 0; i < 20; i++ {
		p.Emit(Event{
			Type:    EventThreat,
			Payload: i,
		})
	}

	stats := p.Stats()
	if stats.Dropped == 0 {
		t.Error("expected some dropped events when buffer is full")
	}
	if stats.Emitted+stats.Dropped != 20 {
		t.Errorf("expected emitted(%d) + dropped(%d) = 20", stats.Emitted, stats.Dropped)
	}

	// Start workers and stop to drain
	p.Start(1)
	p.Stop()
}

func TestEmit100KWithoutBlocking(t *testing.T) {
	p := New(DefaultBufferSize)
	var handled atomic.Int64

	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		handled.Add(1)
		return nil
	}))

	p.Start(4)

	start := time.Now()
	for i := 0; i < 100_000; i++ {
		p.Emit(Event{
			Type:    EventThreat,
			Payload: i,
		})
	}
	emitDuration := time.Since(start)

	p.Stop()

	stats := p.Stats()
	total := stats.Emitted + stats.Dropped
	if total != 100_000 {
		t.Errorf("expected total 100000, got %d (emitted: %d, dropped: %d)", total, stats.Emitted, stats.Dropped)
	}

	// Emitting 100K events should be very fast (non-blocking)
	if emitDuration > 5*time.Second {
		t.Errorf("emit took too long: %v (should be non-blocking)", emitDuration)
	}

	t.Logf("Emitted: %d, Dropped: %d, Handled: %d, Emit duration: %v",
		stats.Emitted, stats.Dropped, handled.Load(), emitDuration)
}

func TestGracefulShutdown(t *testing.T) {
	p := New(1000)
	var handled atomic.Int64

	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		handled.Add(1)
		return nil
	}))

	p.Start(2)

	for i := 0; i < 100; i++ {
		p.Emit(Event{
			Type:    EventThreat,
			Payload: i,
		})
	}

	// Stop should flush all remaining events
	p.Stop()

	if handled.Load() != 100 {
		t.Errorf("expected all 100 events handled after graceful shutdown, got %d", handled.Load())
	}
}

func TestMultipleHandlers(t *testing.T) {
	p := New(100)
	var handler1Count, handler2Count atomic.Int64

	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		handler1Count.Add(1)
		return nil
	}))
	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		handler2Count.Add(1)
		return nil
	}))

	p.Start(2)

	for i := 0; i < 10; i++ {
		p.Emit(Event{Type: EventThreat, Payload: i})
	}

	p.Stop()

	if handler1Count.Load() != 10 {
		t.Errorf("handler1 expected 10, got %d", handler1Count.Load())
	}
	if handler2Count.Load() != 10 {
		t.Errorf("handler2 expected 10, got %d", handler2Count.Load())
	}
}

func TestEventTypes(t *testing.T) {
	p := New(100)
	var threats, activities, perf, audits atomic.Int64

	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		switch event.Type {
		case EventThreat:
			threats.Add(1)
		case EventUserActivity:
			activities.Add(1)
		case EventPerformance:
			perf.Add(1)
		case EventAudit:
			audits.Add(1)
		}
		return nil
	}))

	p.Start(2)

	p.EmitThreat("threat1")
	p.EmitUserActivity("activity1")
	p.EmitPerformance("perf1")
	p.EmitAudit("audit1")

	p.Stop()

	if threats.Load() != 1 {
		t.Errorf("expected 1 threat, got %d", threats.Load())
	}
	if activities.Load() != 1 {
		t.Errorf("expected 1 activity, got %d", activities.Load())
	}
	if perf.Load() != 1 {
		t.Errorf("expected 1 perf, got %d", perf.Load())
	}
	if audits.Load() != 1 {
		t.Errorf("expected 1 audit, got %d", audits.Load())
	}
}

func TestConcurrentEmit(t *testing.T) {
	p := New(10000)
	var handled atomic.Int64

	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		handled.Add(1)
		return nil
	}))

	p.Start(4)

	var wg sync.WaitGroup
	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				p.Emit(Event{Type: EventThreat, Payload: i})
			}
		}()
	}

	wg.Wait()
	p.Stop()

	stats := p.Stats()
	total := stats.Emitted + stats.Dropped
	if total != 10000 {
		t.Errorf("expected total 10000, got %d", total)
	}
}

func TestTimestampAutoSet(t *testing.T) {
	p := New(10)
	var receivedTime time.Time

	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		receivedTime = event.Timestamp
		return nil
	}))

	p.Start(1)

	before := time.Now()
	p.Emit(Event{Type: EventThreat, Payload: "test"})
	p.Stop()

	if receivedTime.Before(before) {
		t.Error("expected timestamp to be auto-set to current time")
	}
}
