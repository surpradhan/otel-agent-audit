package agentauditselect

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// capturingConsumer records every ptrace.Traces forwarded to it.
type capturingConsumer struct {
	mu      sync.Mutex
	batches []ptrace.Traces
}

func (c *capturingConsumer) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = append(c.batches, td)
	return nil
}

func (c *capturingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *capturingConsumer) allSpans() []ptrace.Span {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ptrace.Span
	for _, td := range c.batches {
		rss := td.ResourceSpans()
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				ss := sss.At(j).Spans()
				for k := 0; k < ss.Len(); k++ {
					out = append(out, ss.At(k))
				}
			}
		}
	}
	return out
}

func (c *capturingConsumer) batchCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.batches)
}

// makeTraceID builds a deterministic 16-byte trace ID from a small integer.
func makeTraceID(n int) pcommon.TraceID {
	var id [16]byte
	id[15] = byte(n)
	id[14] = byte(n >> 8)
	return pcommon.TraceID(id)
}

// makeSpanID builds a deterministic 8-byte span ID from a small integer.
func makeSpanID(n int) pcommon.SpanID {
	var id [8]byte
	id[7] = byte(n)
	return pcommon.SpanID(id)
}

// zeroSpanID is the zero SpanID that signals a root span (no parent).
var zeroSpanID = pcommon.SpanID{}

// newSingleSpanTraces builds a ptrace.Traces containing exactly one span.
func newSingleSpanTraces(traceID pcommon.TraceID, spanID pcommon.SpanID, parentSpanID pcommon.SpanID, name string) ptrace.Traces {
	td := ptrace.NewTraces()
	span := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(traceID)
	span.SetSpanID(spanID)
	span.SetParentSpanID(parentSpanID)
	span.SetName(name)
	return td
}

// startProcessor creates and starts a processor, registering Shutdown via t.Cleanup.
func startProcessor(t *testing.T, timeout time.Duration, next consumer.Traces) *agentAuditSelectProcessor {
	t.Helper()
	cfg := &Config{TraceTimeout: timeout}
	p := newProcessor(cfg, nil, next)
	if err := p.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return p
}

// waitForBatch polls cc until batchCount reaches want or deadline elapses.
func waitForBatch(t *testing.T, cc *capturingConsumer, want int, deadline time.Duration) {
	t.Helper()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if cc.batchCount() >= want {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out after %v waiting for %d batch(es); got %d", deadline, want, cc.batchCount())
		}
	}
}

// TestProcessor_CompletesTraceOnRoot sends child1, child2, then root and
// verifies all three are forwarded in a single batch.
func TestProcessor_CompletesTraceOnRoot(t *testing.T) {
	cc := &capturingConsumer{}
	p := startProcessor(t, 30*time.Second, cc)

	traceID := makeTraceID(1)
	child1ID := makeSpanID(1)
	child2ID := makeSpanID(2)
	rootID := makeSpanID(3)
	parentID := makeSpanID(9) // non-zero → child span

	if err := p.ConsumeTraces(context.Background(), newSingleSpanTraces(traceID, child1ID, parentID, "child1")); err != nil {
		t.Fatalf("ConsumeTraces child1: %v", err)
	}
	if err := p.ConsumeTraces(context.Background(), newSingleSpanTraces(traceID, child2ID, parentID, "child2")); err != nil {
		t.Fatalf("ConsumeTraces child2: %v", err)
	}
	if got := cc.batchCount(); got != 0 {
		t.Fatalf("want 0 batches before root; got %d", got)
	}

	if err := p.ConsumeTraces(context.Background(), newSingleSpanTraces(traceID, rootID, zeroSpanID, "root")); err != nil {
		t.Fatalf("ConsumeTraces root: %v", err)
	}

	if got := cc.batchCount(); got != 1 {
		t.Fatalf("want 1 batch after root; got %d", got)
	}
	spans := cc.allSpans()
	if len(spans) != 3 {
		t.Fatalf("want 3 spans; got %d", len(spans))
	}
	names := make(map[string]bool)
	for _, s := range spans {
		names[s.Name()] = true
	}
	for _, want := range []string{"child1", "child2", "root"} {
		if !names[want] {
			t.Errorf("missing span %q", want)
		}
	}
}

// TestProcessor_TimeoutForwardsPartial sends a child span, waits past the
// timeout, and verifies the partial trace is forwarded.
func TestProcessor_TimeoutForwardsPartial(t *testing.T) {
	cc := &capturingConsumer{}
	timeout := 60 * time.Millisecond
	p := startProcessor(t, timeout, cc)

	traceID := makeTraceID(2)
	childID := makeSpanID(1)
	parentID := makeSpanID(9)

	if err := p.ConsumeTraces(context.Background(), newSingleSpanTraces(traceID, childID, parentID, "orphan")); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}

	waitForBatch(t, cc, 1, 5*timeout)

	spans := cc.allSpans()
	if len(spans) != 1 {
		t.Fatalf("want 1 span; got %d", len(spans))
	}
	if spans[0].Name() != "orphan" {
		t.Errorf("want span name 'orphan'; got %q", spans[0].Name())
	}
}

// TestProcessor_ConcurrentTraces verifies that 50 goroutines each sending a
// distinct trace_id → root span all result in 50 forwarded batches.
func TestProcessor_ConcurrentTraces(t *testing.T) {
	const n = 50

	var forwarded atomic.Int64
	var wg sync.WaitGroup

	next := &countingConsumer{count: &forwarded}
	p := startProcessor(t, 30*time.Second, next)

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			traceID := makeTraceID(100 + i)
			childID := makeSpanID(i*2 + 1)
			rootID := makeSpanID(i*2 + 2)
			parentID := makeSpanID(200 + i)

			if err := p.ConsumeTraces(context.Background(),
				newSingleSpanTraces(traceID, childID, parentID, "child")); err != nil {
				t.Errorf("goroutine %d ConsumeTraces child: %v", i, err)
				return
			}
			if err := p.ConsumeTraces(context.Background(),
				newSingleSpanTraces(traceID, rootID, zeroSpanID, "root")); err != nil {
				t.Errorf("goroutine %d ConsumeTraces root: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if got := forwarded.Load(); got != n {
		t.Fatalf("want %d forwarded batches; got %d", n, got)
	}
}

// countingConsumer counts forwarded ptrace.Traces calls.
type countingConsumer struct {
	count *atomic.Int64
}

func (c *countingConsumer) ConsumeTraces(_ context.Context, _ ptrace.Traces) error {
	c.count.Add(1)
	return nil
}

func (c *countingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// TestProcessor_PostForwardSpanPassthrough verifies that a span arriving after
// its trace has been forwarded is passed through immediately (not re-buffered).
func TestProcessor_PostForwardSpanPassthrough(t *testing.T) {
	cc := &capturingConsumer{}
	p := startProcessor(t, 30*time.Second, cc)

	traceID := makeTraceID(3)
	rootID := makeSpanID(1)
	lateID := makeSpanID(2)
	parentID := makeSpanID(9)

	// Send root — triggers forward.
	if err := p.ConsumeTraces(context.Background(), newSingleSpanTraces(traceID, rootID, zeroSpanID, "root")); err != nil {
		t.Fatalf("ConsumeTraces root: %v", err)
	}
	if got := cc.batchCount(); got != 1 {
		t.Fatalf("want 1 batch after root; got %d", got)
	}

	// Send a late span — must be passed through immediately.
	if err := p.ConsumeTraces(context.Background(), newSingleSpanTraces(traceID, lateID, parentID, "late")); err != nil {
		t.Fatalf("ConsumeTraces late: %v", err)
	}

	if got := cc.batchCount(); got != 2 {
		t.Fatalf("want 2 batches after late span; got %d", got)
	}

	p.mu.Lock()
	bufLen := len(p.buffers)
	p.mu.Unlock()
	if bufLen != 0 {
		t.Errorf("want empty buffer after passthrough; got %d entry(ies)", bufLen)
	}

	allSpans := cc.allSpans()
	if len(allSpans) != 2 {
		t.Fatalf("want 2 total spans; got %d", len(allSpans))
	}
	lateFound := false
	for _, s := range allSpans {
		if s.Name() == "late" {
			lateFound = true
		}
	}
	if !lateFound {
		t.Error("late span not found in forwarded output")
	}
}

// TestConfig_Validate exercises all three validation branches.
func TestConfig_Validate(t *testing.T) {
	cases := []struct {
		d       time.Duration
		wantErr bool
	}{
		{-time.Second, true},
		{500 * time.Microsecond, true},
		{minTraceTimeout - 1, true},
		{0, false},
		{minTraceTimeout, false},
		{30 * time.Second, false},
	}
	for _, tc := range cases {
		err := (&Config{TraceTimeout: tc.d}).Validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("TraceTimeout=%v: wantErr=%v, got err=%v", tc.d, tc.wantErr, err)
		}
	}
}

// TestProcessor_ShutdownIdempotent verifies that calling Shutdown twice does
// not panic.
func TestProcessor_ShutdownIdempotent(t *testing.T) {
	cc := &capturingConsumer{}
	cfg := &Config{TraceTimeout: 30 * time.Second}
	p := newProcessor(cfg, nil, cc)
	if err := p.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

// TestProcessor_ShutdownFlushesBuffers verifies that in-progress trace buffers
// (no root received) are forwarded when the processor shuts down.
func TestProcessor_ShutdownFlushesBuffers(t *testing.T) {
	cc := &capturingConsumer{}
	cfg := &Config{TraceTimeout: 30 * time.Second}
	p := newProcessor(cfg, nil, cc)
	if err := p.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start: %v", err)
	}

	traceID := makeTraceID(4)
	childID := makeSpanID(1)
	parentID := makeSpanID(9)

	if err := p.ConsumeTraces(context.Background(), newSingleSpanTraces(traceID, childID, parentID, "orphan")); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	if cc.batchCount() != 0 {
		t.Fatalf("want 0 batches before shutdown; got %d", cc.batchCount())
	}

	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if cc.batchCount() != 1 {
		t.Fatalf("want 1 batch after shutdown flush; got %d", cc.batchCount())
	}
	spans := cc.allSpans()
	if len(spans) != 1 {
		t.Fatalf("want 1 span; got %d", len(spans))
	}
	if spans[0].Name() != "orphan" {
		t.Errorf("want span name 'orphan'; got %q", spans[0].Name())
	}
}
