package pipeline

import (
	"context"
	"testing"
	"time"
)

func BenchmarkPipeline_Emit(b *testing.B) {
	p := New(10000)
	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		return nil
	}))
	p.Start(4)
	defer p.Stop()

	event := Event{
		Type:      EventThreat,
		Timestamp: time.Now(),
		Payload:   "bench",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Emit(event)
	}
}

func BenchmarkPipeline_EmitParallel(b *testing.B) {
	p := New(10000)
	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		return nil
	}))
	p.Start(4)
	defer p.Stop()

	event := Event{
		Type:      EventThreat,
		Timestamp: time.Now(),
		Payload:   "bench",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.Emit(event)
		}
	})
}

func BenchmarkPipeline_EmitThreat(b *testing.B) {
	p := New(10000)
	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		return nil
	}))
	p.Start(4)
	defer p.Stop()

	type fakeThreat struct {
		ID       string
		IP       string
		Path     string
		Severity string
	}

	threat := &fakeThreat{
		ID:       "bench-threat-id",
		IP:       "192.168.1.1",
		Path:     "/api/users",
		Severity: "high",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.EmitThreat(threat)
	}
}

func BenchmarkPipeline_HighContention(b *testing.B) {
	p := New(1000) // Smaller buffer to test backpressure
	p.AddHandler(HandlerFunc(func(ctx context.Context, event Event) error {
		return nil
	}))
	p.Start(2)
	defer p.Stop()

	event := Event{
		Type:      EventThreat,
		Timestamp: time.Now(),
		Payload:   "bench",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.Emit(event)
		}
	})
}
