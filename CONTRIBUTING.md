# Contributing to otel-agent-audit

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Branch model

`main` is **protected and PR-only** — no direct pushes, no force-push, branch
deletion disabled. Rules apply to maintainers too.

Every change lands via:

```
branch off main → commits → PR → green CI → review → squash-merge
```

Before merge, **all** of the following must hold:
- Every required status check is green
- Branch is up to date with `main`
- All review conversations are resolved
- At least one approving review from a maintainer

## Required status checks

<!-- required-checks:start -->
- `Test (Go 1.25)`
- `Test (Go 1.26)`
- `Lint`
- `Build`
- `Required checks in sync`
<!-- required-checks:end -->

> **Drift-guard rule:** Whenever you add, rename, or remove a CI job, update
> `ci.yml`, this block, **and** the GitHub branch-protection required-check
> contexts in the same PR. The `Required checks in sync` job enforces this.

## CI workflow (`.github/workflows/ci.yml`)

| Job | What it does |
|-----|-------------|
| `Test (Go 1.25)` / `Test (Go 1.26)` | `go test -race ./...` on exporter and processor; coverage report for exporter; builds verifier CLI |
| `Lint` | `golangci-lint run` on exporter and processor |
| `Build` | Installs OCB; builds the demo collector distro from `ocb/builder-config.yaml` |
| `Required checks in sync` | Runs the drift-guard script; verifies ci.yml ↔ this block ↔ (optionally) branch protection |

> **Phase B0:** `go.mod`, `ocb/builder-config.yaml`, and the no-op `agentauditexporter` are
> in place. OTel Collector v1.60.0 requires Go 1.25+, so the CI matrix was updated accordingly.

## Commit format

```
<type>: <subject>

<body (optional)>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`.

Never add `Co-Authored-By` lines attributing an AI tool.

## Code review

- A maintainer reviews every PR; address all comments and re-request review.
- **Approval required to merge** — at least one approving review is required
  before a PR can be squash-merged.
- Aim to review within 48 hours.
- The PR author (including an AI agent) never also merges their own PR.

## Development setup

```bash
# Go 1.25 or 1.26 required (OTel Collector v1.60+ requires Go 1.25+)

# Run tests and lint from the exporter sub-module
cd exporter/agentauditexporter
go test -race ./...
golangci-lint run
cd ../..

# Build the demo collector distro
go install go.opentelemetry.io/collector/cmd/builder@v0.154.0
GOWORK=off builder --config=ocb/builder-config.yaml
```

## Release gating

Each Go module in this repo is released independently by pushing a semver tag.
For a Go module the **tag *is* the release** — once pushed, `proxy.golang.org`
serves that version on first request, fetching it directly from the repo. There
is no separate publish step, upload, registry, or token.

Tags follow Go's multi-module convention — the module's directory prefix plus
the version:

| Module | Tag form |
|--------|----------|
| root (`github.com/surpradhan/otel-agent-audit`) | `vX.Y.Z` |
| exporter (`…/exporter/agentauditexporter`) | `exporter/agentauditexporter/vX.Y.Z` |
| processor (`…/processor/agentauditselect`) | `processor/agentauditselect/vX.Y.Z` |

### Maintainer pre-tag checklist

Because a tag is instantly consumable, gating happens **before** tagging. Until a
`release.yml` workflow exists (see below), *the human gate is the maintainer
running this checklist by hand* before cutting the release:

1. The commit being tagged is already **merged to `main`** (an ancestor of
   `origin/main`) — never tag un-reviewed or un-merged code. Fetch first so the
   check reads a current `origin/main`:
   ```bash
   git fetch origin
   git merge-base --is-ancestor <commit> origin/main && echo "ancestor: ok"
   ```
2. CI was green on that commit (it ran as the `main` push build).
3. The tag path matches the module directory (table above) and the version is a
   clean, monotonic semver bump.

Then tag and push, e.g.:
```bash
git tag exporter/agentauditexporter/v0.1.0 <commit>
git push origin exporter/agentauditexporter/v0.1.0
```

> **Released tags are immutable.** Never move, delete, or re-push a released tag
> — the module proxy and checksum database cache it permanently. To correct a
> release, bump to the next version.

### Deferred: automated release gating (`release.yml`)

A token- and environment-scoped, SLSA-attested `release.yml` workflow does
**not** exist yet, and is intentionally deferred. Its machinery only has
something to protect once the project ships **built artifacts** (binary
collector distros, container images, or OS packages). For tag-only Go-module
releases there is no publish step or artifact for it to gate, so an
environment-scoped publish token and SLSA provenance have no surface to apply to
today.

When binary/distro releases arrive, add `release.yml` to:
1. Verify the tagged commit is an ancestor of `origin/main`, and refuse
   otherwise.
2. Require human approval via a GitHub deployment Environment with required
   reviewers before publishing artifacts.
3. Keep the publish token an *environment* secret scoped to that environment —
   not a repo-level secret.
4. Publish with SLSA provenance / GitHub artifact attestation where supported.

`release.yml` is **not** a required PR status check, so the drift-guard
(`Required checks in sync`) ignores it — adding it later does not touch the
required-checks block.

## Branch-protection settings (apply in GitHub UI)

Configure the following on the `main` branch after CI is green on the initial
setup PR:

- **Require a pull request before merging**
  - Required approvals: 1
  - Dismiss stale reviews when new commits are pushed: ✓
- **Require status checks to pass before merging**
  - Require branches to be up to date: ✓
  - Required checks: every context in the required-checks block above
- **Require conversation resolution before merging:** ✓
- **Require linear history:** ✓ (enforces squash-merge)
- **Do not allow bypassing the above settings (enforce for admins):** ✓
- **Allow force pushes:** OFF
- **Allow deletions:** OFF
