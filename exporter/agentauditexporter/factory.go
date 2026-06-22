package agentauditexporter

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter"
)

var typeStr = component.MustNewType("agentaudit")

// NewFactory returns the factory for the agentaudit exporter.
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		typeStr,
		createDefaultConfig,
		exporter.WithTraces(createTracesExporter, component.StabilityLevelDevelopment),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		TraceTimeout:       30 * time.Second,
		CheckpointInterval: 100,
	}
}

func createTracesExporter(
	_ context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Traces, error) {
	oCfg := cfg.(*Config)
	return newAgentAuditExporter(oCfg, set.Logger), nil
}
