# VibeShield

VibeShield is an early-stage security triage tool for AI-generated and
beginner-built web projects. The owner points it at a GitHub repository or a
local folder before deploy and gets a small Agent Fix Pack: concrete findings,
file/line evidence, plain-language risk, and a ready-to-paste prompt for their
coding agent.

The current implementation is the first deterministic Quick Scan slice: secrets
check only, end to end.

## What Works Now

- `vibeshield scan <github-url-or-local-folder>` is wired through the CLI,
  `ScanService`, a stage registry/runner, SQLite state, blob storage, and a
  `SandboxRuntime`.
- GitHub input is cloned inside Microsandbox. Local folders are filtered,
  packaged temporarily, uploaded, and extracted inside Microsandbox.
- `gitleaks` runs in the sandbox. The product path does not fabricate scanner
  output.
- Raw gitleaks JSON is redacted before it enters the blob store.
- Findings outside the snapshot manifest are rejected.
- Reports are written under `~/.vibeshield/runs/<run-id>/` as
  `manifest.json`, `report.json`, `report.md`, and `report.html`.
- With a detected secret, the deterministic verdict is `Critical fix needed`
  and the catalog produces a coding-agent prompt.

Still not done:

- Resume is intentionally not implemented yet.
- Additional scanners are not wired yet: opengrep, syft, trivy, actionlint,
  zizmor, and IaC checks.
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
hash, file list, exclusions, commit SHA when available, and tool versions.

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
