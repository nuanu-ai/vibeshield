# VibeShield

VibeShield is an early-stage security audit pipeline for AI-generated and beginner-built web projects.

The current MVP goal is not a dashboard, GitHub App, or auto-fix system. The goal is to prove the detection core:

> Any repo in, staged confidence out.

A user should be able to point VibeShield at a repo/archive and receive a short set of useful, evidence-backed security findings with clear confidence and coverage boundaries.

## Current Direction

The first implementation should be a local CLI pipeline:

```bash
vibeshield scan /path/to/repo
```

Expected outputs:

```text
report.md
report.json
repo-map.json
coverage.json
findings.json
metrics.json
```

No frontend, backend, GitHub App, PR generation, accounts, or continuous monitoring in the first MVP.

## Technical Shape

Preferred direction for the core is TypeScript/Node orchestration with a language-agnostic analyzer protocol.

That means the main pipeline may run in Node, while individual analyzers can be implemented in any language as long as they return findings through the shared JSON contract.

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
