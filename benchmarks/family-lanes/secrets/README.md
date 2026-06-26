# Secrets Family Fixtures

These committed reports are the first standalone scored `secrets` family lane.

- `planted-secret-report.json` represents a repository with one planted fake
  Stripe key in `src/config.ts`; the expected gitleaks rule is
  `stripe-access-token`.
- `clean-secret-report.json` represents the matching clean control; any direct
  secret finding in that report would score as a false positive.

The planted value is fake and non-live. The truth oracle is fixture construction,
not VibeShield output.
