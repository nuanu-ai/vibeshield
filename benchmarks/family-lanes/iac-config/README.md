# IaC/Config Family Fixtures

These committed reports are a standalone scored `iac-config` family lane.

- `bad-dockerfile-report.json` represents a repository with one intentionally
  weak Dockerfile that does not drop the default root user; the expected Trivy
  config rule is `DS-0002`.
- `clean-dockerfile-report.json` represents the matching clean control; any
  direct IaC/config finding in that report would score as a false positive.

The truth oracle is fixture construction plus the pinned Dockerfile/rule pair,
not VibeShield output. Coverage is proven by the Quick Scan `iac.trivy-config`
check in `assessment.coverage`; these direct-finding fixtures do not need Deep
Static coverage.
