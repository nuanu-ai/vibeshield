# CI/CD Family Fixtures

These committed reports are a standalone scored `ci-cd` family lane.

- `bad-workflow-report.json` represents a repository with one intentionally bad
  GitHub Actions workflow in `.github/workflows/ci.yml`; the expected actionlint
  rule is `workflow-syntax`.
- `clean-workflow-report.json` represents the matching clean control; any direct
  GitHub Actions finding in that report would score as a false positive.

The truth oracle is fixture construction plus the pinned workflow/rule pair, not
VibeShield output. Coverage is proven by the Quick Scan
`github-actions.actionlint` check in `assessment.coverage`; these direct-finding
fixtures do not need Deep Static coverage.
