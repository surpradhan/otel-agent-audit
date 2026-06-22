.PHONY: build test lint clean

# OCB must be installed: go install go.opentelemetry.io/collector/cmd/builder@latest
build:
	builder --config=ocb/builder-config.yaml

test:
	go test -race ./...

lint:
	golangci-lint run

clean:
	rm -rf dist/
