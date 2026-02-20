package pipeline

import (
	"context"
)

// Processor enriches events before they are stored.
// It handles geolocation enrichment, actor linking, severity computation,
// and alert dispatching.
type Processor struct {
	// Enrichers are called in order to enrich events.
	enrichers []Enricher
}

// Enricher modifies an event in-place to add additional data.
type Enricher interface {
	// Enrich adds data to the event. Returns an error if enrichment fails.
	Enrich(ctx context.Context, event *Event) error
}

// EnricherFunc is a function adapter for Enricher.
type EnricherFunc func(ctx context.Context, event *Event) error

// Enrich implements the Enricher interface.
func (f EnricherFunc) Enrich(ctx context.Context, event *Event) error {
	return f(ctx, event)
}

// NewProcessor creates a new event processor.
func NewProcessor() *Processor {
	return &Processor{}
}

// AddEnricher registers an enricher with the processor.
func (p *Processor) AddEnricher(e Enricher) {
	p.enrichers = append(p.enrichers, e)
}

// Process runs all enrichers on the event.
func (p *Processor) Process(ctx context.Context, event *Event) error {
	for _, e := range p.enrichers {
		if err := e.Enrich(ctx, event); err != nil {
			return err
		}
	}
	return nil
}
