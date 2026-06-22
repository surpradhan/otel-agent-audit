package agentauditexporter

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	if f == nil {
		t.Fatal("NewFactory returned nil")
	}
	if f.Type() != typeStr {
		t.Errorf("unexpected factory type: got %v, want %v", f.Type(), typeStr)
	}
}

func TestConsumeTraces(t *testing.T) {
	exp := newAgentAuditExporter(&Config{})
	if err := exp.ConsumeTraces(context.Background(), ptrace.NewTraces()); err != nil {
		t.Errorf("ConsumeTraces returned unexpected error: %v", err)
	}
}

func TestCapabilities(t *testing.T) {
	exp := newAgentAuditExporter(&Config{})
	caps := exp.Capabilities()
	if caps.MutatesData {
		t.Error("MutatesData should be false for no-op exporter")
	}
}

func TestStartShutdown(t *testing.T) {
	exp := newAgentAuditExporter(&Config{})
	if err := exp.Start(context.Background(), nil); err != nil {
		t.Errorf("Start returned unexpected error: %v", err)
	}
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown returned unexpected error: %v", err)
	}
}
