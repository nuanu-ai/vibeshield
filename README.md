# VibeShield

VibeShield is an early-stage security triage tool for AI-generated and
beginner-built web projects. The owner points it at a GitHub repository or a
local folder before deploy and gets a small Agent Fix Pack: concrete findings,
file/line evidence, plain-language risk, and a ready-to-paste prompt for their
coding agent.

The current implementation is a deterministic Quick Scan slice. It runs the
sandboxed scanner toolchain, records truthful coverage, and turns detected
secrets, dependency issues, workflow issues, IaC findings, and code-pattern
hits into deterministic Fix Pack actions.

## What Works Now

- `vibeshield scan <github-url-or-local-folder>` is wired through the CLI,
  `ScanService`, a stage registry/runner, SQLite state, blob storage, and a
  `SandboxRuntime`.
- GitHub input is cloned inside Microsandbox. Local folders are filtered,
  packaged temporarily, uploaded, and extracted inside Microsandbox.
- `gitleaks`, `opengrep`, `syft`, `trivy`, `actionlint`, and `zizmor` run in
  the sandbox when the inventory says they apply. Non-applicable checks are
  skipped with a recorded reason.
- Raw scanner JSON is redacted before it enters the blob store.
- Findings outside the snapshot manifest are rejected.
- Reports include a coverage table showing checked, skipped, failed, or
  degraded checks.
- Reports are written under `~/.vibeshield/runs/<run-id>/` as
  `manifest.json`, `report.json`, `report.md`, and `report.html`.
- With detected blocking findings, the deterministic verdict and catalog
  produce prioritized coding-agent prompts.

Still not done:

- Resume is intentionally not implemented yet.
- The one OpenRouter/Opus remediation enhancement call is not wired yet; the
  current slice uses the deterministic catalog fallback.
- The live Microsandbox acceptance run still requires a local toolchain image.

## Quickstart

Requirements:

- Node 24+
- pnpm 10+
- Docker or compatible image builder
- Microsandbox installed locally

Install dependencies:

```bash
pnpm install
```

Build and load the toolchain image:

```bash
docker build -t vibeshield-toolchain:latest -f toolchain/Dockerfile toolchain
docker save vibeshield-toolchain:latest -o /tmp/vibeshield-toolchain.tar
~/.microsandbox/bin/msb load -t vibeshield-toolchain:latest -i /tmp/vibeshield-toolchain.tar
```

Run a scan:

```bash
pnpm scan https://github.com/owner/repo
pnpm scan /path/to/local/folder
```

Override state or image tag when needed:

```bash
VIBESHIELD_STATE_ROOT=/tmp/vibeshield-state pnpm scan /path/to/local/folder
VIBESHIELD_TOOLCHAIN_TAG=vibeshield-toolchain:latest pnpm scan /path/to/local/folder
```

## Run Output

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

The source tree is not stored as an artifact. The manifest records the source
hash, file list, exclusions, commit SHA when available, toolchain image tag,
tool versions, and vulnerability DB freshness when the tool exposes it.

## Development

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm exec tsx scripts/make-planted-secret-fixture.ts
```

The default test suite uses `FakeSandboxRuntime`; it does not boot a VM. The live
Microsandbox smoke test is skipped by default and can be run explicitly when the
toolchain image is loaded:

```bash
pnpm exec vitest run tests/microsandbox-runtime.smoke.test.ts
```

## Documentation

- [Architecture notes](docs/architecture.md)
- [Agent guidance](AGENTS.md)

When documents disagree, prefer the most recent implementation-oriented decision
document in `docs/`.
