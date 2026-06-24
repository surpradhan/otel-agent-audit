.PHONY: build test lint clean demo

# OCB must be installed: go install go.opentelemetry.io/collector/cmd/builder@v0.154.0
build:
	GOWORK=off builder --config=ocb/builder-config.yaml

test:
	cd exporter/agentauditexporter && go test -race ./...

lint:
	cd exporter/agentauditexporter && golangci-lint run

clean:
	rm -rf dist/

# demo generates a 3-span fixture trace, chains+signs it, and verifies it offline.
# No Collector, LLM key, or network connection required.
demo:
	cd exporter/agentauditexporter && go run ./cmd/demo
