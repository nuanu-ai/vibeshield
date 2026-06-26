# Dependencies Family Fixtures

These committed reports are a standalone scored `dependencies` family lane.

- `vulnerable-npm-report.json` represents a repository with `lodash@4.17.20`
  pinned in `package-lock.json`; the expected dependency finding is
  `CVE-2021-23337` from Trivy.
- `clean-npm-report.json` represents the matching patched control with no
  vulnerable dependency finding; any direct dependency finding in that report
  would score as a false positive.

The truth oracle is fixture construction plus the pinned manifest/CVE pair, not
VibeShield output. Coverage is proven by the Quick Scan `dependencies.trivy`
check in `assessment.coverage`; these direct-finding fixtures do not need Deep
Static coverage.
