# VibeShield

VibeShield is an early-stage security audit pipeline for AI-generated and beginner-built web projects.

The current product slice is not a dashboard, GitHub App, or auto-fix system. The goal is to prove the scan pipeline:

> GitHub repo in, inspectable run artifacts out.

The current scan output is a facts-only AppSec repository map plus deterministic scanner results. The map is not a security verdict; deeper security findings come later after the repository map and runtime boundary are stable.

## Current Direction

The first implementation should be a local CLI pipeline:

```bash
vibeshield scan https://github.com/owner/repo
```

Target outputs:

```text
run.json
events.jsonl
report.md
report.json
repo-map.json
coverage.json
findings.json
metrics.json
```

The first implementation may produce only a smaller subset.

No frontend, backend, GitHub App, PR generation, accounts, or continuous monitoring in the current product slice.

## Technical Shape

Preferred direction for the core is TypeScript/Node orchestration with simple, inspectable steps.

The first implementation should avoid a heavy analyzer framework. Later steps may call external tools when that becomes useful.

The local CLI runs deterministic baseline jobs, builds curated Pi context,
collects a facts-only repository map, validates evidence, and writes an
artifact-driven report. The default runtime sandbox path uses the official
`@daytona/sdk` adapter. Tests use a fake Daytona adapter only as a local test
double. A live scan requires Daytona and OpenRouter credentials and must not fall
back to cloning a hostile repository on the host.

The core concepts are:

- repo intake and classification;
- universal baseline hygiene;
- ecosystem analyzers;
- AI-assisted repository mapping;
- verifier;
- scoring, deduplication, and suppression;
- short reports with coverage.

## Documentation

Project docs live in [docs/](./docs/).

Start here:

- [Architecture](./docs/architecture.md)
- [Product idea](./docs/idea.md)

## Working Principles

See [AGENTS.md](./AGENTS.md) for repository conventions and agent instructions.

## Local Development

```bash
pnpm install
pnpm lint
pnpm typecheck
pnpm test
pnpm scan https://github.com/owner/repo
pnpm smoke:daytona https://github.com/octocat/Hello-World
pnpm smoke:pi-daytona https://github.com/owner/repo
```

`pnpm scan` runs the development CLI form of `vibeshield scan`. A successful
live scan requires `DAYTONA_API_KEY` and `OPENROUTER_API_KEY`;
`DAYTONA_API_URL` and `DAYTONA_TARGET` are optional SDK overrides. Put these
values in `.env` or export them in the shell. `pnpm smoke:daytona` is the live
Daytona scan path; it exits clearly when required keys are missing.
`pnpm smoke:pi-daytona` is retained as a focused Pi-in-Daytona smoke through
OpenRouter. The fake adapter in
`src/sandbox/fake-daytona.ts` is for non-live acceptance tests only.

Current runs write inspectable artifacts under each local run directory,
including `outputs/inventory.json`, `outputs/baseline-summary.json`,
`outputs/baseline/tool-availability.json`,
`outputs/baseline/syft-sbom.json`, `outputs/pi-context-pack.json`,
repository map section artifacts under `outputs/repo-map/`,
`outputs/repository-map.json`,
per-stage redacted Pi progress/log artifacts under `outputs/pi/<stage>/`, and
`report.md`. The current map sections are coverage/structure, stack/build/deps,
entrypoints, auth/config/secrets, storage/integrations/infra, operation sinks,
data flows, and trust boundaries.
