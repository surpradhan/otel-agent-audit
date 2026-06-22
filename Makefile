.PHONY: build test lint clean

# OCB must be installed: go install go.opentelemetry.io/collector/cmd/builder@v0.154.0
build:
	GOWORK=off builder --config=ocb/builder-config.yaml

test:
	cd exporter/agentauditexporter && go test -race ./...

lint:
	cd exporter/agentauditexporter && golangci-lint run

clean:
	rm -rf dist/
