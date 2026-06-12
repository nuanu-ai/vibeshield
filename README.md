# VibeShield

VibeShield is an early-stage security audit pipeline for AI-generated and beginner-built web projects.

The current MVP goal is not a dashboard, GitHub App, or auto-fix system. The goal is to prove the detection core:

> Any repo in, staged confidence out.

A user should be able to point VibeShield at a GitHub repository URL and receive a short set of useful, evidence-backed security findings with clear confidence and coverage boundaries.

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

Phase 0 has a local CLI skeleton with scenario tests for GitHub URL intake, run
artifacts, sandbox lifecycle, read-only inventory, and failure reporting. The
default runtime sandbox path uses the official `@daytona/sdk` adapter. Tests use
a fake Daytona adapter only as a local test double. A live scan requires Daytona
credentials and must not fall back to cloning a hostile repository on the host.

The core concepts are:

- repo intake and classification;
- universal baseline hygiene;
- ecosystem analyzers;
- AI security question generation;
- verifier;
- scoring, deduplication, and suppression;
- short reports with coverage.

## Documentation

Project docs live in [docs/](./docs/).

Start here:

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
```

`pnpm scan` runs the development CLI form of `vibeshield scan`. A successful
live scan requires `DAYTONA_API_KEY`, `DAYTONA_API_URL`, and `DAYTONA_TARGET`.
`pnpm smoke:daytona` is the live AC0.1 check path; it exits clearly when those
environment variables are missing. The fake adapter in
`src/sandbox/fake-daytona.ts` is for non-live acceptance tests only.
