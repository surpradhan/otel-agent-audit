package agentauditexporter

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

type agentAuditExporter struct{}

func newAgentAuditExporter(_ *Config) *agentAuditExporter {
	return &agentAuditExporter{}
}

func (e *agentAuditExporter) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (e *agentAuditExporter) Shutdown(_ context.Context) error {
	return nil
}

func (e *agentAuditExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (e *agentAuditExporter) ConsumeTraces(_ context.Context, _ ptrace.Traces) error {
	return nil
}
