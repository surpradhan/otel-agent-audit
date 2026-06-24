# Security Policy

## Scope

This policy covers the following components of `otel-agent-audit`:

- `exporter/agentauditexporter` — the audit exporter, WAL, fsync, and checkpoint logic
- `exporter/agentauditexporter/cmd/otel-agent-audit-verify` — the verifier CLI
- `internal/canonical` and `internal/record` — chain serialization and signing internals

Out of scope: third-party dependencies (report those to their upstream projects),
the OCB build tooling, and the demo fixture generator.

For the documented design limits of the audit chain itself (malicious-operator
scenarios, single-replica constraints, etc.), see
[docs/threat-model.md](docs/threat-model.md).

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting instead:

1. Go to the **Security** tab of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the details — a minimal reproducer or proof-of-concept is appreciated
   but not required for an initial report.

GitHub's private reporting keeps the disclosure confidential until a fix is
available.

Alternatively: email surabhi7pradhan@gmail.com with subject line `[otel-agent-audit] Security Report`.

---

## Supported Versions

This project is pre-1.0. Only the **latest commit on `main`** (and any
associated release tag) receives security attention. Older tagged versions do
not receive backported fixes.

| Version | Supported |
|---------|-----------|
| Latest `main` / latest release tag | Yes |
| Older tags | No |

---

## Response Expectations

This is a solo-maintained project. Best-effort acknowledgement is the honest
commitment:

- **Acknowledgement:** aim to acknowledge reports within a few business days,
  but no SLA is promised.
- **Fix timeline:** depends on severity and complexity; no fixed timeline is
  guaranteed.
- **Disclosure:** coordinated disclosure is preferred — please allow reasonable
  time for a fix before publishing details publicly.

No legal safe-harbor assurance is made here. The intent is to handle reports in
good faith and to credit reporters (unless they prefer to remain anonymous).

---

## What to Include in a Report

- Component affected (see Scope above)
- Description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (even a partial one helps)
- Any suggested mitigations you have in mind
