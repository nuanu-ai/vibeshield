# AGENTS.md

Repository-level guidance for coding agents working on VibeShield.

Keep this file short and practical. Put product and architecture detail in the
relevant files under `docs/` instead of duplicating it here.

## Project Context

VibeShield is an early-stage security audit pipeline for AI-generated and
beginner-built web projects.

The current product slice focuses on proving the detection core through a local CLI
pipeline that accepts a GitHub repository URL or local Git worktree root:

```bash
vibeshield scan <github-url-or-local-path>
```

Primary orientation:

- `README.md`: concise project overview.
- `docs/`: current product, architecture, and planning documents.

## Repository Layout

- `AGENTS.md`: coding-agent guidance.
- `README.md`: human entry point.
- `docs/`: product, architecture, and planning documents.

Implementation directories may be added as the product takes shape. When adding a
new top-level area, keep the README or relevant docs clear enough for the next
agent to orient quickly.

## Engineering Principles

- **KISS**: prefer the simplest design that validates the current detection
  hypothesis.
- **DRY**: share schemas, contracts, and analyzer plumbing when duplication
  creates real maintenance risk.
- **YAGNI**: add infrastructure, abstractions, and dependencies when the current
  current product slice needs them.

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
- For local path scans, require a Git worktree root and use Git-filtered
  snapshots; do not add a non-Git directory fallback.
- Do not add legacy paths, fallbacks, migrations, or backward compatibility for
  old runs/contracts unless the user explicitly asks for it.

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
- run the local CLI in dev: `pnpm scan <github-url-or-local-path>`;
- resume a failed run from durable artifacts: `pnpm resume /path/to/run-directory`;
- run the live Microsandbox smoke:
  `pnpm exec vitest run tests/microsandbox-runtime.smoke.test.ts`;
- build package output: `pnpm build`.

The current default CLI path uses `MicrosandboxRuntime` with the local
`vibeshield-toolchain` image. OpenRouter is optional and only enhances Fix Pack
wording; if `OPENROUTER_API_KEY` is missing or invalid, the deterministic catalog
fallback is used. If the sandbox/toolchain is unavailable, the CLI must fail
clearly rather than running scanners on the host. `FakeSandboxRuntime` is only a
local test double.

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
