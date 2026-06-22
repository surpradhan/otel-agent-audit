#!/usr/bin/env python3
"""
Drift-guard: verifies that the CI job names in ci.yml, the required-check
contexts listed in CONTRIBUTING.md, and (optionally) the live GitHub
branch-protection required contexts are all in sync.

Exits 0 when every list matches; exits 1 on any mismatch and prints a diff.

(1) ci.yml → CONTRIBUTING.md always runs (no credentials needed; works on forks).
(2) ci.yml → GitHub API runs only when CHECKS_SYNC_TOKEN + GITHUB_REPOSITORY are set.

Rule: whenever you add/rename/remove a CI job, update ci.yml, the
CONTRIBUTING.md required-checks block, AND branch protection in the same PR.
"""

import json
import os
import re
import sys
import urllib.request

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CI_YML = os.path.join(REPO_ROOT, ".github", "workflows", "ci.yml")
CONTRIBUTING_MD = os.path.join(REPO_ROOT, "CONTRIBUTING.md")


def load_ci_contexts(path: str) -> set[str]:
    """Derive the set of check-context strings from ci.yml job names + matrix."""
    with open(path) as f:
        ci = yaml.safe_load(f)

    contexts: set[str] = set()
    for job_id, job in ci.get("jobs", {}).items():
        name_template: str = job.get("name", job_id)
        matrix: dict = job.get("strategy", {}).get("matrix", {})

        dims: list[tuple[str, list]] = [
            (k, [str(v) for v in vs])
            for k, vs in matrix.items()
            if k not in ("include", "exclude")
        ]

        if not dims:
            contexts.add(name_template)
            continue

        combos: list[dict] = [{}]
        for key, values in dims:
            combos = [{**c, key: v} for c in combos for v in values]

        for combo in combos:
            name = name_template
            for key, val in combo.items():
                name = name.replace("${{ matrix." + key + " }}", val)
            contexts.add(name)

    return contexts


def load_contributing_contexts(path: str) -> set[str]:
    """Parse the <!-- required-checks:start/end --> block from CONTRIBUTING.md."""
    with open(path) as f:
        content = f.read()

    match = re.search(
        r"<!-- required-checks:start -->(.*?)<!-- required-checks:end -->",
        content,
        re.DOTALL,
    )
    if not match:
        print("ERROR: required-checks block not found in CONTRIBUTING.md")
        sys.exit(1)

    contexts: set[str] = set()
    for line in match.group(1).splitlines():
        m = re.match(r"^\s*-\s+`(.+?)`\s*$", line)
        if m:
            contexts.add(m.group(1))
    return contexts


def load_github_contexts(repo: str, branch: str, token: str) -> set[str]:
    """Fetch live branch-protection required contexts from the GitHub API."""
    url = (
        f"https://api.github.com/repos/{repo}/branches/{branch}"
        "/protection/required_status_checks"
    )
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    with urllib.request.urlopen(req) as resp:
        data = json.load(resp)
    return set(data.get("contexts", []))


def compare(label_a: str, a: set[str], label_b: str, b: set[str]) -> bool:
    if a == b:
        print(f"✅  {label_a} and {label_b} are in sync ({len(a)} checks)")
        return True
    print(f"❌  MISMATCH: {label_a} vs {label_b}")
    for ctx in sorted(a - b):
        print(f"   + in {label_a} only:  {ctx!r}")
    for ctx in sorted(b - a):
        print(f"   - in {label_b} only:  {ctx!r}")
    return False


def main() -> None:
    ok = True

    ci_contexts = load_ci_contexts(CI_YML)
    print(f"ci.yml contexts ({len(ci_contexts)}): {sorted(ci_contexts)}")

    contrib_contexts = load_contributing_contexts(CONTRIBUTING_MD)
    print(f"CONTRIBUTING.md contexts ({len(contrib_contexts)}): {sorted(contrib_contexts)}")

    ok &= compare("ci.yml", ci_contexts, "CONTRIBUTING.md", contrib_contexts)

    token = os.environ.get("CHECKS_SYNC_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    branch = os.environ.get("GITHUB_BASE_REF") or "main"

    if token and repo:
        print(f"\nFetching GitHub branch-protection contexts for {repo}@{branch} …")
        try:
            gh_contexts = load_github_contexts(repo, branch, token)
            print(f"GitHub contexts ({len(gh_contexts)}): {sorted(gh_contexts)}")
            ok &= compare("ci.yml", ci_contexts, "GitHub branch protection", gh_contexts)
        except Exception as exc:
            print(f"⚠️   Could not fetch GitHub contexts: {exc}")
    else:
        print("\n(Skipping GitHub API check — CHECKS_SYNC_TOKEN not set)")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
