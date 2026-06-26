# Deterministic Code Pattern Fixtures

These committed reports are a standalone scored `deterministic-code-patterns`
family lane.

- `eval-code-report.json` represents a repository with one intentionally
  dangerous JavaScript `eval` call in `src/app.js`; the expected OpenGrep rule
  is `vibeshield.javascript-eval`.
- `clean-code-report.json` represents the matching clean control; any direct
  code-pattern finding in that report would score as a false positive.

The truth oracle is fixture construction plus the pinned code/rule pair, not
VibeShield output. Coverage is proven by the Quick Scan `code-patterns.opengrep`
check in `assessment.coverage`; these direct-finding fixtures do not need Deep
Static coverage.
