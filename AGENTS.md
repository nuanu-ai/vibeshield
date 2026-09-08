# AGENTS.md

Repository-level guidance for coding agents working on VibeShield.

Keep this file short and practical. Put product and architecture detail in the
relevant files under `docs/` instead of duplicating it here.

## Project Context

VibeShield is a private web service for AI-generated and beginner-built web
projects. Someone submits a public GitHub repository URL, watches the checks run,
and gets a short list of jobs to do with prompts for their coding agent.

```bash
pnpm start   # http://127.0.0.1:3000
```

Primary orientation:

- `README.md`: what the product is and how to run it.
- `docs/architecture.md`: how the service is put together.
- `docs/private-web-browser.md`: pages, routes, diagnostics and acceptance.

The earlier CLI pipeline and its deep-static experiment are still in the tree
with their tests. They are not the product and not a current promise. Do not
extend them; removing them is outstanding work.

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
- Product input is a public GitHub repository URL. Do not add local paths,
  private repositories or credentials to the scan flow.
- Never run repository code: no install, build, test, migration or package
  script, on the host or in the sandbox.
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
- build/load the pinned scanner image: `pnpm toolchain:prepare`;
- run the service in dev: `pnpm dev`;
- run the built service: `pnpm build && pnpm start`;
- lint: `pnpm lint`;
- typecheck: `pnpm typecheck`;
- fast tests: `pnpm test`;
- all four of the above: `pnpm check`;
- real engines in Microsandbox: `pnpm test:live`.

The fast suite supplies controlled scanner exports at the sandbox boundary and
does not boot a VM. `pnpm test:live` is a separate mandatory serial check: it
fails clearly when the runtime, image, binaries, rules or versions are missing,
and a skipped live run does not count as acceptance. If the sandbox or toolchain
is unavailable, the service must fail clearly rather than running scanners on the
host.

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
