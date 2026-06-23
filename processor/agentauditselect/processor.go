// Package agentauditselect implements an OpenTelemetry Collector processor that
// buffers spans per trace and forwards each trace as a complete unit.
//
// Design: spans arrive in arbitrary batches. The processor holds them in
// per-trace buffers keyed by trace_id. A trace is emitted (forwarded to the
// next consumer as a single ptrace.Traces call) in one of two ways:
//
//  1. Root detected: when a span with parent_span_id == "" arrives, all buffered
//     spans for that trace are forwarded immediately.
//
//  2. Timeout: a background goroutine fires every trace_timeout/2. Any trace
//     whose last-seen time exceeds trace_timeout is forwarded as-is, even if no
//     root span has been observed.
//
// Spans that arrive after a trace has been forwarded are passed through
// immediately (the downstream exporter will drop them with a warning; the
// processor is not responsible for dedup).
//
// Each trace is emitted as its own ptrace.Traces call — spans from different
// traces are never grouped into one call.
//
// The emitted map (which tracks forwarded trace IDs to enable pass-through of
// late-arriving spans) is TTL-evicted on each background sweep at 2*trace_timeout,
// bounding its size to roughly 2*trace_timeout worth of completed trace IDs.
package agentauditselect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// minTraceTimeout is the smallest value Validate() accepts for TraceTimeout
// when explicitly set. Values smaller than this are impractical for a tracing
// buffer and would produce a sub-nanosecond ticker interval on division by 2.
const minTraceTimeout = time.Millisecond

// capturedSpan is a deep copy of a span together with its resource and scope
// metadata, safe to hold across ConsumeTraces calls.
type capturedSpan struct {
	resourceAttrs     pcommon.Map
	resourceSchemaURL string
	scopeName         string
	scopeVersion      string
	scopeSchemaURL    string
	scopeAttrs        pcommon.Map
	span              ptrace.Span
}

// traceBuffer holds copied spans for one in-progress trace.
type traceBuffer struct {
	spans    []capturedSpan
	lastSeen time.Time
}

// scopeKey identifies a unique instrumentation scope within a ResourceSpans.
// It includes scope attributes so that scopes sharing the same name, version,
// and schema URL but carrying different attributes are not merged.
type scopeKey struct{ schemaURL, name, version, attrsKey string }

type agentAuditSelectProcessor struct {
	cfg          *Config
	logger       *zap.Logger
	next         consumer.Traces
	mu           sync.Mutex
	shutdownOnce sync.Once
	// buffers holds in-progress traces not yet forwarded. Guarded by mu.
	buffers map[string]*traceBuffer
	// emitted records trace IDs already forwarded, keyed to the time of
	// forwarding. Entries are evicted after 2*traceTimeout on each background
	// sweep. Guarded by mu.
	emitted map[string]time.Time
	stopCh  chan struct{}
	doneCh  chan struct{}
}

func newProcessor(cfg *Config, logger *zap.Logger, next consumer.Traces) *agentAuditSelectProcessor {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &agentAuditSelectProcessor{
		cfg:     cfg,
		logger:  logger,
		next:    next,
		buffers: make(map[string]*traceBuffer),
		emitted: make(map[string]time.Time),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

func (p *agentAuditSelectProcessor) Start(_ context.Context, _ component.Host) error {
	go p.backgroundWorker(p.traceTimeout())
	return nil
}

// Shutdown stops the background sweep goroutine and flushes any in-progress
// trace buffers. Traces that received spans but no root span before shutdown
// are forwarded as partial so the downstream exporter can seal whatever was
// received. No WAL-backed recovery is performed (that is out of scope for B3b).
//
// Shutdown is idempotent: a second call is a no-op (the stopCh is guarded by
// sync.Once). Flush errors from individual traces are collected and returned
// as a combined error.
func (p *agentAuditSelectProcessor) Shutdown(ctx context.Context) error {
	p.shutdownOnce.Do(func() { close(p.stopCh) })
	select {
	case <-p.doneCh:
	case <-ctx.Done():
		p.logger.Warn("agentauditselect: Shutdown context expired waiting for background worker")
	}

	// Flush all in-progress buffers.
	p.mu.Lock()
	type pending struct {
		traceID string
		traces  ptrace.Traces
	}
	toFlush := make([]pending, 0, len(p.buffers))
	for traceID, buf := range p.buffers {
		toFlush = append(toFlush, pending{traceID, buildTraces(buf)})
		delete(p.buffers, traceID)
	}
	p.mu.Unlock()

	var errs []error
	for _, f := range toFlush {
		p.logger.Warn("agentauditselect: flushing in-progress trace at shutdown",
			zap.String("trace_id", f.traceID))
		if err := p.next.ConsumeTraces(ctx, f.traces); err != nil {
			p.logger.Error("agentauditselect: flush at shutdown failed",
				zap.String("trace_id", f.traceID), zap.Error(err))
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *agentAuditSelectProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeTraces buffers incoming spans per trace, forwarding any trace whose
// root span has been received.
func (p *agentAuditSelectProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	now := time.Now()

	var passThrough []ptrace.Traces // spans for already-emitted traces

	type pendingForward struct {
		traceID string
		traces  ptrace.Traces
	}
	var toForward []pendingForward

	p.mu.Lock()
	// rootSeen tracks trace IDs that received a root span in this batch to
	// avoid forwarding the same trace twice if two root spans arrive together.
	rootSeen := make(map[string]struct{})

	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i)
		sss := rs.ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			ss := sss.At(j)
			spans := ss.Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				traceID := span.TraceID().String()

				// Pass through post-forward spans without re-buffering.
				if _, done := p.emitted[traceID]; done {
					passThrough = append(passThrough, buildSingleSpanTraces(rs, ss, span))
					continue
				}

				// Deep-copy the span and all metadata so we can hold them past
				// this ConsumeTraces call.
				cs := capturedSpan{
					resourceSchemaURL: rs.SchemaUrl(),
					scopeName:         ss.Scope().Name(),
					scopeVersion:      ss.Scope().Version(),
					scopeSchemaURL:    ss.SchemaUrl(),
					span:              ptrace.NewSpan(),
				}
				cs.resourceAttrs = pcommon.NewMap()
				rs.Resource().Attributes().CopyTo(cs.resourceAttrs)
				cs.scopeAttrs = pcommon.NewMap()
				ss.Scope().Attributes().CopyTo(cs.scopeAttrs)
				span.CopyTo(cs.span)

				buf := p.buffers[traceID]
				if buf == nil {
					buf = &traceBuffer{lastSeen: now}
					p.buffers[traceID] = buf
				}
				buf.spans = append(buf.spans, cs)
				buf.lastSeen = now

				if span.ParentSpanID().IsEmpty() {
					rootSeen[traceID] = struct{}{}
				}
			}
		}
	}

	// Build the forwarding list for all traces that received a root this batch.
	for traceID := range rootSeen {
		buf := p.buffers[traceID]
		if buf == nil {
			continue
		}
		toForward = append(toForward, pendingForward{
			traceID: traceID,
			traces:  buildTraces(buf),
		})
		delete(p.buffers, traceID)
		p.emitted[traceID] = now
	}
	p.mu.Unlock()

	// Forward pass-through spans (independent copies — no lock needed).
	for _, pt := range passThrough {
		if err := p.next.ConsumeTraces(ctx, pt); err != nil {
			return err
		}
	}

	// Forward complete traces.
	for _, f := range toForward {
		if err := p.next.ConsumeTraces(ctx, f.traces); err != nil {
			return err
		}
	}

	return nil
}

// backgroundWorker sweeps for timed-out traces every traceTimeout/2.
func (p *agentAuditSelectProcessor) backgroundWorker(timeout time.Duration) {
	defer close(p.doneCh)
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case now := <-ticker.C:
			p.sweepTimedOut(context.Background(), now, timeout)
		}
	}
}

// sweepTimedOut collects and forwards all traces idle for at least timeout,
// then evicts stale entries from the emitted map (older than 2*timeout).
func (p *agentAuditSelectProcessor) sweepTimedOut(ctx context.Context, now time.Time, timeout time.Duration) {
	type pendingForward struct {
		traceID string
		traces  ptrace.Traces
		idle    time.Duration
	}

	p.mu.Lock()
	var pending []pendingForward
	for traceID, buf := range p.buffers {
		if now.Sub(buf.lastSeen) >= timeout {
			pending = append(pending, pendingForward{
				traceID: traceID,
				traces:  buildTraces(buf),
				idle:    now.Sub(buf.lastSeen),
			})
			delete(p.buffers, traceID)
			p.emitted[traceID] = now
		}
	}
	// Evict emitted entries older than 2*timeout. Any legitimate late-arriving
	// span for a forwarded trace arrives well within this window.
	for traceID, emitTime := range p.emitted {
		if now.Sub(emitTime) >= 2*timeout {
			delete(p.emitted, traceID)
		}
	}
	p.mu.Unlock()

	for _, f := range pending {
		p.logger.Info("agentauditselect: forwarding timed-out trace",
			zap.String("trace_id", f.traceID),
			zap.Duration("idle", f.idle))
		if err := p.next.ConsumeTraces(ctx, f.traces); err != nil {
			p.logger.Error("agentauditselect: forwarding timed-out trace failed",
				zap.String("trace_id", f.traceID), zap.Error(err))
		}
	}
}

// traceTimeout returns the configured timeout, falling back to 30s for zero
// or any value below minTraceTimeout (belt-and-suspenders; Validate rejects
// values in the [1ns, minTraceTimeout) range at config-load time).
func (p *agentAuditSelectProcessor) traceTimeout() time.Duration {
	if p.cfg.TraceTimeout >= minTraceTimeout {
		return p.cfg.TraceTimeout
	}
	return 30 * time.Second
}

// attrsMapKey returns a stable, collision-resistant string key for an attribute
// map. Keys and values are Go-quoted so embedded delimiters cannot produce
// false matches between distinct attribute sets.
func attrsMapKey(attrs pcommon.Map) string {
	pairs := make([]string, 0, attrs.Len())
	attrs.Range(func(k string, v pcommon.Value) bool {
		pairs = append(pairs, fmt.Sprintf("%q=%q", k, v.AsString()))
		return true
	})
	sort.Strings(pairs)
	return strings.Join(pairs, "\x01")
}

// resourceAttrsKey returns a stable key for a (resource attrs, schema URL) pair.
func resourceAttrsKey(attrs pcommon.Map, schemaURL string) string {
	return schemaURL + "\x00" + attrsMapKey(attrs)
}

// buildTraces assembles a ptrace.Traces from a buffer. Each distinct
// (resource attrs, resource schema URL) combination produces its own
// ResourceSpans; each distinct (scope schema URL, scope name, scope version,
// scope attrs) produces its own ScopeSpans within that ResourceSpans.
func buildTraces(buf *traceBuffer) ptrace.Traces {
	td := ptrace.NewTraces()
	if len(buf.spans) == 0 {
		return td
	}

	type rsEntry struct {
		rs    ptrace.ResourceSpans
		ssMap map[scopeKey]ptrace.ScopeSpans
	}
	rsMap := make(map[string]*rsEntry)

	for _, cs := range buf.spans {
		rk := resourceAttrsKey(cs.resourceAttrs, cs.resourceSchemaURL)
		rse, ok := rsMap[rk]
		if !ok {
			rs := td.ResourceSpans().AppendEmpty()
			cs.resourceAttrs.CopyTo(rs.Resource().Attributes())
			rs.SetSchemaUrl(cs.resourceSchemaURL)
			rse = &rsEntry{rs: rs, ssMap: make(map[scopeKey]ptrace.ScopeSpans)}
			rsMap[rk] = rse
		}

		sk := scopeKey{cs.scopeSchemaURL, cs.scopeName, cs.scopeVersion, attrsMapKey(cs.scopeAttrs)}
		ss, ok := rse.ssMap[sk]
		if !ok {
			ss = rse.rs.ScopeSpans().AppendEmpty()
			ss.Scope().SetName(cs.scopeName)
			ss.Scope().SetVersion(cs.scopeVersion)
			cs.scopeAttrs.CopyTo(ss.Scope().Attributes())
			ss.SetSchemaUrl(cs.scopeSchemaURL)
			rse.ssMap[sk] = ss
		}
		cs.span.CopyTo(ss.Spans().AppendEmpty())
	}
	return td
}

// buildSingleSpanTraces wraps one span in its own ptrace.Traces, preserving
// resource attributes, schema URLs, and scope attributes.
func buildSingleSpanTraces(rs ptrace.ResourceSpans, ss ptrace.ScopeSpans, span ptrace.Span) ptrace.Traces {
	td := ptrace.NewTraces()
	newRS := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().CopyTo(newRS.Resource().Attributes())
	newRS.SetSchemaUrl(rs.SchemaUrl())
	newSS := newRS.ScopeSpans().AppendEmpty()
	newSS.Scope().SetName(ss.Scope().Name())
	newSS.Scope().SetVersion(ss.Scope().Version())
	ss.Scope().Attributes().CopyTo(newSS.Scope().Attributes())
	newSS.SetSchemaUrl(ss.SchemaUrl())
	span.CopyTo(newSS.Spans().AppendEmpty())
	return td
}
