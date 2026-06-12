# AGENTS.md

Repository-level guidance for coding agents working on VibeShield.

Keep this file short and practical. Put product and architecture detail in the
relevant files under `docs/` instead of duplicating it here.

## Project Context

VibeShield is an early-stage security audit pipeline for AI-generated and
beginner-built web projects.

The current MVP focuses on proving the detection core through a local CLI
pipeline that accepts a GitHub repository URL:

```bash
vibeshield scan https://github.com/owner/repo
```

Primary orientation:

- `README.md`: concise project overview.
- `docs/`: current product, architecture, and planning documents.

## Repository Layout

- `AGENTS.md`: coding-agent guidance.
- `README.md`: human entry point.
- `docs/`: product, architecture, and planning documents.

Implementation directories may be added as the MVP takes shape. When adding a
new top-level area, keep the README or relevant docs clear enough for the next
agent to orient quickly.

## Engineering Principles

- **KISS**: prefer the simplest design that validates the current detection
  hypothesis.
- **DRY**: share schemas, contracts, and analyzer plumbing when duplication
  creates real maintenance risk.
- **YAGNI**: add infrastructure, abstractions, and dependencies when the current
  MVP needs them.

Prefer boring, inspectable code over clever orchestration. Keep behavior easy to
debug from files on disk.

## Scope Rules

- Use `README.md` and the relevant files in `docs/` as the source of truth for
  current product and architecture decisions.
- When docs appear to conflict, prefer the most specific and most recently
  updated decision document, then update or flag the conflict.
- Treat major product or architecture changes as documentation changes too.
- Keep `AGENTS.md` focused on durable engineering guidance, not detailed design.
- Preserve existing user changes and avoid broad refactors while doing focused
  work.
- Treat repositories being analyzed by VibeShield as untrusted input.

## Stack Direction

The planned core direction is TypeScript/Node orchestration with simple,
inspectable steps.

Use structured JSON contracts for run state, findings, coverage, metrics, and
reports when they are useful. Do not design a heavy analyzer framework before
the first working scan flow exists.

## Commands

Project tooling:

- install: `pnpm install`;
- lint: `pnpm lint`;
- typecheck: `pnpm typecheck`;
- test: `pnpm test`;
- run the local CLI in dev: `pnpm scan https://github.com/owner/repo`;
- run the live Daytona smoke scan:
  `pnpm smoke:daytona https://github.com/octocat/Hello-World`;
- run the experimental Pi-in-Daytona smoke:
  `pnpm smoke:pi-daytona https://github.com/xor777/ai-spam-detector`;
- build package output: `pnpm build`.

The current default CLI path uses the real `@daytona/sdk` adapter. Live scans
need `DAYTONA_API_KEY` and `OPENROUTER_API_KEY`; `DAYTONA_API_URL` and
`DAYTONA_TARGET` are optional SDK overrides. If credentials are missing, the CLI
must fail clearly rather than cloning an untrusted repo on the host.
`FakeDaytonaSandboxProvider` is only a local test double.

## Commit Hygiene

Optimize commits for future `git bisect`.

- Prefer Conventional Commit prefixes when they fit (`feat:`, `fix:`, `test:`,
  `docs:`, `chore:`, `refactor:`), but prioritize accurate, atomic history over
  forced labels.
- Prefer small, logical commits: one behavior change, tooling change, or docs
  status update per commit.
- Keep commits green on the main development path: run the relevant
  lint/typecheck/test command before committing.
- Commit tests with the behavior they protect unless a separate test-only commit
  still leaves the tree green.
- Keep `package.json` and lockfile changes in the same commit.
- Update docs in the same commit as the behavior change when the docs describe
  that behavior.
- Do not mix mechanical formatting with product or runtime logic.
- Do not commit generated or local artifacts such as `node_modules`, `dist`,
  `runs`, logs, or temporary scan outputs.

## Verification

Before finishing a coding task:

- run the most relevant lint/typecheck/test command available;
- verify generated outputs are inspectable and kept out of git when appropriate;
- update docs when behavior, scope, or commands change;
- report any missing checks clearly in the final response.

For docs-only changes, check that referenced files exist and that links point to
current paths.

## Done Means

A task is complete when:

- the requested change is implemented;
- relevant docs stay consistent with the change;
- the working tree contains only intended changes;
- verification was run or the verification gap is explicit.
