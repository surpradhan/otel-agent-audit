# Contributing to otel-agent-audit

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
- `Test (Go 1.22)`
- `Test (Go 1.23)`
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
| `Test (Go 1.22)` / `Test (Go 1.23)` | `go test -race ./...` with coverage report |
| `Lint` | `golangci-lint run` |
| `Build` | Installs OCB; builds the demo collector distro from `ocb/builder-config.yaml` |
| `Required checks in sync` | Runs the drift-guard script; verifies ci.yml ↔ this block ↔ (optionally) branch protection |

> **Phase B0 note:** `Test` and `Build` require `go.mod` and
> `ocb/builder-config.yaml` to exist. Both are created in Phase B0.

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
# Go 1.22 or 1.23 required
go test -race ./...
golangci-lint run

# Build the demo collector distro (requires ocb/builder-config.yaml)
go install go.opentelemetry.io/collector/cmd/builder@latest
builder --config=ocb/builder-config.yaml
```

## Release gating

Releases are cut by pushing a semver tag (e.g. `v0.1.0`), handled by a
separate `release.yml` workflow — **not** a required PR check (so the
drift-guard ignores it).

The release workflow must:
1. Verify the tagged commit is an ancestor of `origin/main`.
2. Require human approval via a GitHub deployment Environment with required
   reviewers before publishing.
3. Never publish code that has not been reviewed and merged to `main`.
4. Keep the publish token (e.g. `GOMODULE_TOKEN`) as an *environment* secret
   scoped to the release environment — not a repo-level secret accessible to
   all jobs.
5. Publish with SLSA provenance / GitHub artifact attestation where supported.

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
