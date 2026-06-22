# VibeShield

VibeShield is an early-stage Quick Scan for AI-built and beginner-built web
projects. Point it at a public GitHub repository or a local Git worktree root
before deploy and it returns a small Agent Fix Pack: the few issues that matter,
file/line evidence, a plain-language risk explanation, and a ready-to-paste
prompt for a coding agent.

The current slice proves the deterministic security core. Scanners run inside
Microsandbox, the host records truthful coverage and reports, and the verdict,
finding set, priority, and action candidates are computed by rules before any
model call. OpenRouter can improve the wording of the Fix Pack, but the catalog
fallback produces the same actions when the key is absent or the model response
is invalid.

## What Works

- `vibeshield scan <github-url-or-local-git-root>` through the local CLI.
- Public GitHub repositories are cloned inside Microsandbox.
- Local input must be the Git worktree root; VibeShield packages a Git-filtered
  snapshot and includes `.env` files so secret checks can catch local leaks.
- `gitleaks`, `opengrep`, `syft`, `trivy`, `actionlint`, and `zizmor` run in the
  sandbox when inventory says they apply.
- Vulnerability databases refresh on each run. Stale or failed required coverage
  is shown as degraded/failed and cannot produce a green verdict.
- Raw scanner output is redacted before it enters the blob store.
- Reports are written as terminal output, `report.json`, `report.md`, and
  `report.html`.
- The OpenRouter remediation enhancer uses `OPENROUTER_API_KEY` and
  `VIBESHIELD_REMEDIATION_MODEL`; missing or invalid model output falls back to
  deterministic catalog copy.

Not done yet: resume, private repositories, zip upload, runtime validation, PDF
reports, and SaaS isolation hardening.

## Quickstart

Requirements:

- Node 24+
- pnpm 10+
- Docker or a compatible image builder
- Microsandbox installed locally

Install dependencies:

```bash
pnpm install
```

Build and load the scanner toolchain image:

```bash
docker build -t vibeshield-toolchain:latest -f toolchain/Dockerfile toolchain
docker save vibeshield-toolchain:latest -o /tmp/vibeshield-toolchain.tar
~/.microsandbox/bin/msb load -t vibeshield-toolchain:latest -i /tmp/vibeshield-toolchain.tar
```

Optional `.env` values:

```bash
OPENROUTER_API_KEY=
VIBESHIELD_REMEDIATION_MODEL=anthropic/claude-sonnet-4.6
VIBESHIELD_STATE_ROOT=
VIBESHIELD_TOOLCHAIN_TAG=vibeshield-toolchain:latest
```

Run a scan:

```bash
pnpm scan https://github.com/owner/repo
pnpm scan /path/to/local/git-worktree-root
```

## Output

The terminal output is the owner-facing result:

```text
VibeShield Quick Scan
Verdict: Critical fix needed
Fix Pack: 3 actions (OpenRouter enhanced; deterministic verdict/actions; 1 critical, 2 high)

Coverage
  [ok] secrets.gitleaks
  [ok] dependencies.trivy
  [skipped] github-actions.actionlint - no GitHub Actions workflows found

Agent Fix Pack
1. Remove the committed Stripe secret
   Evidence: src/config.ts:4
   Agent prompt:
     Remove the committed Stripe key and load it from environment instead.
```

State and blobs live under `~/.vibeshield` by default:

```text
~/.vibeshield/
├── state.sqlite
├── blobs/sha256/<prefix>/<hash>
└── runs/<run-id>/
    ├── manifest.json
    ├── report.json
    ├── report.md
    └── report.html
```

The source tree is not stored as an artifact. The manifest records source
origin, commit SHA when available, file hashes, exclusions, source hash,
toolchain image tag, tool versions, and vulnerability DB freshness where known.

Every report includes the static-scan limitation: VibeShield does not run the
app, so authorization logic and runtime behavior are not checked.

## Development

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm exec tsx scripts/make-planted-secret-fixture.ts
```

The default test suite uses `FakeSandboxRuntime`; it does not boot a VM. The
live Microsandbox smoke test is skipped by default and can be run explicitly
after the toolchain image is loaded:

```bash
pnpm exec vitest run tests/microsandbox-runtime.smoke.test.ts
```

## Documentation

- [Architecture notes](docs/architecture.md)
- [Stage 1 plan](docs/stage-1-deterministic-security-core-plan.md)
- [Agent guidance](AGENTS.md)

When documents disagree, prefer the most recent implementation-oriented
decision document in `docs/`.
