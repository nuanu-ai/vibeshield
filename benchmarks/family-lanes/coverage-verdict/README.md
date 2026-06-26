# Coverage And Verdict Fixtures

These committed reports are a standalone scored lane for coverage and verdict
behavior.

- `mixed-language-partial-report.json` represents a repository where Deep Static
  supports the main language but reports one unsupported PHP file as
  `language_support=partial`; dependency usage is complete at `1/1`.
- `deploy-blocking-report.json` represents a repository with a deploy-blocking
  issue and an expected `not-ready-to-deploy` verdict.

The truth oracle is fixture construction plus the pinned coverage and verdict
contract, not VibeShield output. These fixtures are scored through
`expectedVerdict` and `coverage` expectations instead of direct finding or static
hypothesis denominators.
