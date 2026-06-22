# CLAUDE.md — Agent working conventions for otel-agent-audit

## Project context

- **Language / runtime:** Go 1.22+
- **Build:** OpenTelemetry Collector Builder (OCB); `go install go.opentelemetry.io/collector/cmd/builder@latest`
- **Module path:** `github.com/surpradhan/otel-agent-audit`
- **Test command:** `go test -race ./...`
- **Lint command:** `golangci-lint run`
- **Build command:** `builder --config=ocb/builder-config.yaml`
- **Default branch:** `main` (protected, PR-only)

## Commit format

```
<type>: <subject>

<body (optional)>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`.

**Never add `Co-Authored-By` lines attributing an AI tool.**

## Human-in-the-loop guardrails (non-negotiable)

### Never self-merge to `main`
The agent that authors a PR is never also the one that reviews or merges it.
Stop at "PR open, CI green, awaiting human review." CI-green ≠ reviewed.

### Contributor grace period
Do not self-implement issues tagged `good-first-issue` for **3 days** after
opening unless explicitly marked urgent. External contributors deserve the
chance to pick them up first.

### Contributor PR reviews
When reviewing a PR from an external contributor:
- Leave feedback and let the contributor apply it.
- Only push direct fixes to their branch when the owner explicitly says to.
- Credit the contributor on merge; comment the linked issue closed.

## Drift-guard discipline

Whenever you add, rename, or remove a CI job, **update all three in the same PR**:
1. `.github/workflows/ci.yml` — the job definition
2. `CONTRIBUTING.md` — the `<!-- required-checks:start/end -->` block
3. GitHub branch-protection required-check contexts (human applies this in the UI)

The `Required checks in sync` CI job enforces that (1) and (2) stay in sync
and will fail the PR if they diverge.

## Chain-format discipline

`internal/canonical` and `internal/record` are **load-bearing** — their output
is what gets hashed. Any change to canonical serialization or the audit-record
schema is a **breaking chain-format change** and requires:
- A `schema_version` bump
- A new cross-impl fixture in the test suite
- A note in `docs/audit-record-schema.md`

Do not refactor canonical/record without updating the fixtures.

## What NOT to do

- Do not add the `batch` processor upstream of `agentauditexporter` — it
  regroups/reorders spans and defeats deterministic ordering.
- Do not introduce a second global `prev_hash` — chaining is per-trace only.
- Do not propose flat causation-ID fields (`causation_id`, `parent_session_id`)
  to the OTel SIG — OTel models causation via span context/links.
- Do not claim EU AI Act compliance certification — Art. 12 is technology-neutral
  and no finalized technical standard exists to certify against.
