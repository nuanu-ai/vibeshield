# VibeShield

VibeShield is an early-stage security audit pipeline for AI-generated and beginner-built web projects.

The current MVP goal is not a dashboard, GitHub App, or auto-fix system. The goal is to prove the scan pipeline:

> GitHub repo in, inspectable run artifacts out.

The current walking skeleton is an evidence-backed repository map, not a security verdict or findings report. Security findings come in later phases after the project map and runtime boundary are stable.

## Current Direction

The first implementation should be a local CLI pipeline:

```bash
vibeshield scan https://github.com/owner/repo
```

Target outputs over the MVP:

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

The first walking skeleton may produce only a smaller subset.

No frontend, backend, GitHub App, PR generation, accounts, or continuous monitoring in the first MVP.

## Technical Shape

Preferred direction for the core is TypeScript/Node orchestration with simple, inspectable steps.

The first implementation should avoid a heavy analyzer framework. Later steps may call external tools when that becomes useful.

Phase 1 extends the local CLI skeleton with deterministic baseline jobs,
curated Pi context, staged Pi repository mapping, evidence validation, and an
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
- [MVP plan](./docs/mvp-plan.md)
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
including `outputs/inventory.v1.json`, `outputs/baseline-summary.v1.json`,
`outputs/baseline/tool-availability.v1.json`,
`outputs/baseline/syft-sbom.json`, `outputs/pi-context-pack.v1.json`,
`outputs/entry-points.v1.json`, `outputs/sensitive-sinks.v1.json`,
`outputs/data-flows.v1.json`, `outputs/project-understanding.v1.json`,
per-stage `outputs/*-semantic-evaluation.v1.json` verdicts,
per-stage redacted Pi progress/log artifacts under `outputs/pi/<stage>/`, and
`report.md`.
