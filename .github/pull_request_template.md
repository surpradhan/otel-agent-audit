## Description
<!-- What does this PR do? -->

## Why
<!-- Why is this change needed? What problem does it solve? -->

## Changes
<!-- Bullet-point summary of the key changes -->

## How to Test
<!-- Steps to manually test or verify the change -->
```bash
go test -race ./...
golangci-lint run
```

## Screenshots / Demo
<!-- If applicable, add a demo run or output snippet -->

## Related Issues
<!-- Closes # -->

## Checklist
- [ ] `go test -race ./...` passes locally
- [ ] `golangci-lint run` passes locally
- [ ] Tests added for any new behavior
- [ ] Docs updated (README, threat-model.md, audit-record-schema.md, etc.) if applicable
- [ ] No undocumented breaking changes — chain format or schema version bumped if needed
- [ ] Commit format followed (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `chore:`)
- [ ] Branch is up to date with `main`
- [ ] `ci.yml`, `CONTRIBUTING.md` required-checks block, and branch-protection contexts updated together (if CI jobs changed)

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] Test
- [ ] Chore / dependency update
