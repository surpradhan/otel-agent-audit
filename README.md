# otel-agent-audit

A signed-audit OpenTelemetry Collector component for agent traces. Point your
existing OTel Collector at it and get a **tamper-evident, independently
verifiable audit log** with zero re-instrumentation.

**Use this if** you run OTel-instrumented AI agents and need a cryptographically
verifiable record of what happened. Governance and guardrail decisions that are
already present in your spans get sealed into a per-trace hash-chain, signed with
Ed25519, and made checkable by anyone holding only the public key. It is
**observability only** and does not enforce or block.

### See it work in 30 seconds

Runs entirely locally, no Collector or network required (needs Go 1.25+):

```bash
make demo
```

This generates a fixture trace, builds the chain locally, and runs the verifier
end to end. Annotated source:
[exporter/agentauditexporter/cmd/demo](exporter/agentauditexporter/cmd/demo).

> ⚠️ **Experimental, not independently audited.** The hash-chain and Ed25519
> signed checkpoints provide tamper-evidence **on honest infrastructure**. They do
> **not** protect against a malicious log operator who holds the signing key and
> rewrites the whole log. Review the code and the
> [threat model](docs/threat-model.md) before relying on it for governance or
> incident-response purposes.

---

## How it works

```
[ OTel-instrumented agents ]
        │  OTLP (gen_ai.* spans)
        ▼
[ OTel Collector — audit pipeline ]
  receivers:  otlp
  processors: [ memory_limiter, agentauditselect ]   ← buffers each trace until root arrives
  exporters:  [ agentaudit ]                          ← chain → sign → seal
        │
        ▼
[ audit.jsonl + checkpoint.jsonl ]
        │
        ▼
[ otel-agent-audit-verify ]  ← independent CLI; verifies signatures, chain, and checkpoints
```

Each trace produces a **per-trace hash-chain** ordered deterministically by
`(start_time_unix_nano, span_id)`. Every entry is signed with Ed25519. Signed
checkpoints commit to all sealed trace tips at a configurable cadence. Because
verification uses only the **public key**, anyone with the log plus the public
key can verify independently, with no secrets required.

---

## Quickstart

**Prerequisites:** Go **1.25+** (the modules and the pinned Collector v0.154.0
require it).

### 1. Build

```bash
# Install the OTel Collector Builder (OCB)
go install go.opentelemetry.io/collector/cmd/builder@v0.154.0

# Build the demo collector distro
GOWORK=off builder --config=ocb/builder-config.yaml
# Output: ./dist/otel-agent-audit-collector

# Build the verifier CLI
cd exporter/agentauditexporter
go build -o ../../dist/otel-agent-audit-verify ./cmd/otel-agent-audit-verify
```

### 2. Generate an Ed25519 key pair

```bash
openssl genpkey -algorithm ed25519 -out audit-private.pem
openssl pkey -in audit-private.pem -pubout -out audit-public.pem
```

### 3. Configure the Collector

```yaml
receivers:
  otlp:
    protocols:
      grpc:

processors:
  memory_limiter:
    check_interval: 5s
    limit_mib: 512
  agentauditselect:
    trace_timeout: 30s

exporters:
  agentaudit:
    log_path:        /var/log/audit/audit.jsonl
    checkpoint_path: /var/log/audit/checkpoint.jsonl
    wal_path:        /var/log/audit/wal.jsonl
    key_path:        /etc/audit/audit-private.pem
    trace_timeout:   30s
    checkpoint_interval: 100
    fsync_log: true   # default; set false to disable for high-throughput testing

service:
  pipelines:
    traces:
      receivers:  [otlp]
      processors: [memory_limiter, agentauditselect]
      exporters:  [agentaudit]
```

> **Important:** `agentauditselect` must be the last processor, immediately
> before `agentaudit`. Do not place `batch` between them (see Operational
> constraints below).

### 4. Feed traces, then verify

Once spans flow through the collector, run the verifier:

```bash
dist/otel-agent-audit-verify \
  -key-file audit-public.pem \
  /var/log/audit/audit.jsonl \
  /var/log/audit/checkpoint.jsonl
```

Expected output on a clean log:

```
Traces processed:      42
Checkpoints processed: 1
Status: OK
```

---

## Operational constraints (read before deploying)

- **Single writer.** Run as **exactly one** Collector instance. Multiple writers
  to the same sink produce spurious verification failures.
- **No `batch` upstream.** Do **not** place the `batch` processor upstream of
  `agentauditexporter`. It regroups spans and defeats deterministic ordering.
- **Not a compliance certification.** **EU AI Act Article 12** is
  technology-neutral and does not mandate cryptographic audit logs. This
  component is a useful tamper-evidence tool, not a certified compliance product.
  See [docs/threat-model.md](docs/threat-model.md#6-eu-ai-act-article-12--disclaimer).

---

## Documentation

| Document | Contents |
|----------|----------|
| [docs/threat-model.md](docs/threat-model.md) | What the chain guarantees, what it does not, and the malicious-operator limit |
| [docs/verification.md](docs/verification.md) | Verifier CLI reference, key distribution, exit codes |
| [docs/audit-record-schema.md](docs/audit-record-schema.md) | Versioned record schema, field-by-field; entry construction protocol |
| [docs/guardrail-mapping.md](docs/guardrail-mapping.md) | How policy/guardrail spans map to audit records |

---

## Development

```bash
# Run tests with race detector (required before any PR)
cd exporter/agentauditexporter && go test -race ./...
cd processor/agentauditselect && go test -race ./...

# Lint
cd exporter/agentauditexporter && golangci-lint run
cd processor/agentauditselect && golangci-lint run

# Build the demo collector distro
GOWORK=off builder --config=ocb/builder-config.yaml
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch model, commit format, and
drift-guard conventions.

---

## License

MIT. See [LICENSE](LICENSE).
