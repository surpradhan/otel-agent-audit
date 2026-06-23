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
package agentauditselect

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// capturedSpan is a deep copy of a span together with its resource and scope
// metadata, safe to hold across ConsumeTraces calls.
type capturedSpan struct {
	resourceAttrs pcommon.Map
	scopeName     string
	scopeVersion  string
	span          ptrace.Span
}

// traceBuffer holds copied spans for one in-progress trace.
type traceBuffer struct {
	spans    []capturedSpan
	lastSeen time.Time
}

type agentAuditSelectProcessor struct {
	cfg    *Config
	logger *zap.Logger
	next   consumer.Traces
	mu     sync.Mutex
	// buffers holds in-progress traces not yet forwarded. Guarded by mu.
	buffers map[string]*traceBuffer
	// emitted records trace IDs already forwarded, so post-forward spans can be
	// passed through without re-buffering. Guarded by mu.
	emitted map[string]struct{}
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
		emitted: make(map[string]struct{}),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

func (p *agentAuditSelectProcessor) Start(_ context.Context, _ component.Host) error {
	go p.backgroundWorker(p.traceTimeout())
	return nil
}

func (p *agentAuditSelectProcessor) Shutdown(_ context.Context) error {
	close(p.stopCh)
	<-p.doneCh
	return nil
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
	// Track which trace IDs have had a root span detected in this batch to
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

				// Deep-copy the span so we can hold it past this ConsumeTraces call.
				cs := capturedSpan{
					scopeName:    ss.Scope().Name(),
					scopeVersion: ss.Scope().Version(),
					span:         ptrace.NewSpan(),
				}
				cs.resourceAttrs = pcommon.NewMap()
				rs.Resource().Attributes().CopyTo(cs.resourceAttrs)
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

	// Build forwarding list for all traces that received a root this batch.
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
		p.emitted[traceID] = struct{}{}
	}
	p.mu.Unlock()

	// Forward pass-through spans (no lock needed — these are independent copies).
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

// sweepTimedOut collects and forwards all traces idle for at least timeout.
func (p *agentAuditSelectProcessor) sweepTimedOut(ctx context.Context, now time.Time, timeout time.Duration) {
	type pendingForward struct {
		traceID string
		traces  ptrace.Traces
	}

	p.mu.Lock()
	var pending []pendingForward
	for traceID, buf := range p.buffers {
		if now.Sub(buf.lastSeen) >= timeout {
			p.logger.Info("agentauditselect: forwarding timed-out trace",
				zap.String("trace_id", traceID),
				zap.Duration("idle", now.Sub(buf.lastSeen)))
			pending = append(pending, pendingForward{
				traceID: traceID,
				traces:  buildTraces(buf),
			})
			delete(p.buffers, traceID)
			p.emitted[traceID] = struct{}{}
		}
	}
	p.mu.Unlock()

	for _, f := range pending {
		if err := p.next.ConsumeTraces(ctx, f.traces); err != nil {
			p.logger.Error("agentauditselect: forwarding timed-out trace failed",
				zap.String("trace_id", f.traceID), zap.Error(err))
		}
	}
}

func (p *agentAuditSelectProcessor) traceTimeout() time.Duration {
	if p.cfg.TraceTimeout > 0 {
		return p.cfg.TraceTimeout
	}
	return 30 * time.Second
}

// buildTraces assembles a ptrace.Traces from a buffer. All spans share one
// ResourceSpans; scopes are grouped by (name, version).
func buildTraces(buf *traceBuffer) ptrace.Traces {
	td := ptrace.NewTraces()
	if len(buf.spans) == 0 {
		return td
	}

	rs := td.ResourceSpans().AppendEmpty()
	buf.spans[0].resourceAttrs.CopyTo(rs.Resource().Attributes())

	type scopeKey struct{ name, version string }
	ssMap := make(map[scopeKey]ptrace.ScopeSpans)

	for _, cs := range buf.spans {
		key := scopeKey{cs.scopeName, cs.scopeVersion}
		ss, ok := ssMap[key]
		if !ok {
			ss = rs.ScopeSpans().AppendEmpty()
			ss.Scope().SetName(cs.scopeName)
			ss.Scope().SetVersion(cs.scopeVersion)
			ssMap[key] = ss
		}
		dst := ss.Spans().AppendEmpty()
		cs.span.CopyTo(dst)
	}
	return td
}

// buildSingleSpanTraces wraps one span in its own ptrace.Traces with resource
// and scope metadata preserved.
func buildSingleSpanTraces(rs ptrace.ResourceSpans, ss ptrace.ScopeSpans, span ptrace.Span) ptrace.Traces {
	td := ptrace.NewTraces()
	newRS := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().CopyTo(newRS.Resource().Attributes())
	newSS := newRS.ScopeSpans().AppendEmpty()
	newSS.Scope().SetName(ss.Scope().Name())
	newSS.Scope().SetVersion(ss.Scope().Version())
	span.CopyTo(newSS.Spans().AppendEmpty())
	return td
}
