package pipeline

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultBufferSize is the default ring buffer capacity.
const DefaultBufferSize = 10000

// Pipeline is an async event pipeline that uses a ring buffer channel.
// Events are emitted without blocking and processed by background goroutines.
type Pipeline struct {
	events   chan Event
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	handlers []Handler
	mu       sync.RWMutex
	dropped  atomic.Int64
	emitted  atomic.Int64
}

// Handler processes events from the pipeline.
type Handler interface {
	// Handle processes a single event. It should not block for long.
	Handle(ctx context.Context, event Event) error
}

// HandlerFunc is a function adapter for Handler.
type HandlerFunc func(ctx context.Context, event Event) error

// Handle implements the Handler interface.
func (f HandlerFunc) Handle(ctx context.Context, event Event) error {
	return f(ctx, event)
}

// New creates a new event pipeline with the given buffer size.
// If bufferSize is 0, DefaultBufferSize is used.
func New(bufferSize int) *Pipeline {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{
		events: make(chan Event, bufferSize),
		ctx:    ctx,
		cancel: cancel,
	}
}

// AddHandler registers an event handler with the pipeline.
func (p *Pipeline) AddHandler(h Handler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers = append(p.handlers, h)
}

// Start begins processing events with the specified number of workers.
func (p *Pipeline) Start(workers int) {
	if workers <= 0 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

// Emit sends an event to the pipeline without blocking.
// If the buffer is full, the event is dropped to avoid blocking the caller.
func (p *Pipeline) Emit(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	select {
	case p.events <- event:
		p.emitted.Add(1)
	default:
		p.dropped.Add(1)
	}
}

// EmitThreat is a convenience method to emit a threat event.
func (p *Pipeline) EmitThreat(payload interface{}) {
	p.Emit(Event{
		Type:      EventThreat,
		Timestamp: time.Now(),
		Payload:   payload,
	})
}

// EmitUserActivity is a convenience method to emit a user activity event.
func (p *Pipeline) EmitUserActivity(payload interface{}) {
	p.Emit(Event{
		Type:      EventUserActivity,
		Timestamp: time.Now(),
		Payload:   payload,
	})
}

// EmitPerformance is a convenience method to emit a performance event.
func (p *Pipeline) EmitPerformance(payload interface{}) {
	p.Emit(Event{
		Type:      EventPerformance,
		Timestamp: time.Now(),
		Payload:   payload,
	})
}

// EmitAudit is a convenience method to emit an audit event.
func (p *Pipeline) EmitAudit(payload interface{}) {
	p.Emit(Event{
		Type:      EventAudit,
		Timestamp: time.Now(),
		Payload:   payload,
	})
}

// Stats returns pipeline statistics.
func (p *Pipeline) Stats() PipelineStats {
	return PipelineStats{
		Emitted:    p.emitted.Load(),
		Dropped:    p.dropped.Load(),
		BufferSize: len(p.events),
		BufferCap:  cap(p.events),
	}
}

// PipelineStats contains pipeline operational statistics.
type PipelineStats struct {
	// Emitted is the total number of events successfully emitted.
	Emitted int64 `json:"emitted"`

	// Dropped is the total number of events dropped due to a full buffer.
	Dropped int64 `json:"dropped"`

	// BufferSize is the current number of events in the buffer.
	BufferSize int `json:"buffer_size"`

	// BufferCap is the total buffer capacity.
	BufferCap int `json:"buffer_cap"`
}

// Stop gracefully shuts down the pipeline, processing remaining events.
func (p *Pipeline) Stop() {
	p.cancel()
	close(p.events)
	p.wg.Wait()
}

func (p *Pipeline) worker() {
	defer p.wg.Done()
	for event := range p.events {
		p.mu.RLock()
		handlers := make([]Handler, len(p.handlers))
		copy(handlers, p.handlers)
		p.mu.RUnlock()

		for _, h := range handlers {
			if err := h.Handle(p.ctx, event); err != nil {
				log.Printf("[sentinel] pipeline handler error: %v", err)
			}
		}
	}
}
