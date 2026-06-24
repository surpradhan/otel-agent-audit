# otel-agent-audit

A signed-audit OpenTelemetry Collector component for agent traces.
Point your existing OTel Collector at it and get a **tamper-evident,
independently verifiable audit log** — zero re-instrumentation required.

> **Experimental / development-stage software — not independently audited**
> This project has not undergone a third-party security audit. The hash-chain and
> Ed25519 signed checkpoints provide tamper-evidence on honest infrastructure, but
> they do **not** protect against a malicious log operator who holds the signing key
> and rewrites the entire log. See [docs/threat-model.md](docs/threat-model.md) for
> the full set of guarantees and limits. Review the code before relying on it for
> governance or incident-response purposes.

> **Operational constraints (read before deploying)**
> - Run as **exactly one** Collector instance. Multiple writers to the same sink produce spurious verification failures.
> - Do **not** place the `batch` processor upstream of `agentauditexporter`. It regroups spans and defeats deterministic ordering.
> - **EU AI Act Article 12** is technology-neutral and does not mandate cryptographic audit logs. This component is a useful tamper-evidence tool, not a certified compliance product. See [docs/threat-model.md](docs/threat-model.md#6-eu-ai-act-article-12--disclaimer).

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
verification uses only the **public key**, anyone with the log + public key can
verify independently — no secrets needed.

---

## Quickstart

### 1. Build

```bash
# Install the OTel Collector Builder (OCB)
go install go.opentelemetry.io/collector/cmd/builder@v0.154.0

# Build the demo collector distro
GOWORK=off builder --config=ocb/builder-config.yaml
# Output: dist/otelcol-agentaudit (or dist/ depending on OCB version)

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

> **Important:** `agentauditselect` must be the last processor, immediately before `agentaudit`. Do not place `batch` between them.

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

### 5. Offline demo

```bash
make demo
```

This generates a fixture trace, builds the chain locally, and runs the
verifier — no Collector or network needed. See
[exporter/agentauditexporter/cmd/demo](exporter/agentauditexporter/cmd/demo)
for the annotated source.

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

MIT — see [LICENSE](LICENSE).
