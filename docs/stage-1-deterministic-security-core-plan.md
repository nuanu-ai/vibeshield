# Stage 1 Plan: deterministic Quick Scan + one AI fix-pack call

VibeShield is a security triage for people who build apps with AI agents. They
point it at a repo before they ship and get a small **Agent Fix Pack**: a few
things that actually matter, each with the file, a plain-language reason, and a
ready-to-paste prompt for their coding agent. The magic moment is one line:
"Don't deploy yet — there's a live key in `src/config.ts:12`. Here's why, and
here's the prompt to fix it."

Iteration 1 builds the reliable deterministic machine that produces this, end to
end, on a real repo. Facts, severity, priority, and the final verdict are
computed by rules. Exactly one bounded AI call turns the deterministic findings
into the plain-language explanation and the coding-agent prompt; if it fails, a
built-in template produces the same result less elaborately.

## Locked decisions

These were decided with the owner. They are the frame; the rest of the plan
follows from them.

- Runtime: **Microsandbox, network on**, one sandbox per run. GitHub input is
  cloned inside the sandbox; a local folder is copied in. Daytona is removed.
- Scanners are not a pinned/published image. They come from a **simple,
  rebuildable Dockerfile** — nothing precious to maintain, lose, or recover.
- **Vulnerability databases are refreshed on every run** over the network.
- The source tree is **not stored** as an artifact. Only a small manifest is
  kept (commit SHA, file list with hashes, exclusions, tool + DB versions).
- Input is a **public GitHub URL or a local folder**. No "must be a git repo
  root". Private repos and zip upload come later.
- Iteration 1 ships the **full check set** (secrets, code patterns, SBOM,
  dependencies, GitHub Actions, IaC). Internally it is proven one check first,
  then widened.
- The one AI call uses **Claude Opus 4.8 (high reasoning effort)** via Pi, runs
  **on the host** (it needs the findings, not the repo), and is **enhancement
  only** — the deterministic result is complete without it.
- If the AI call is unavailable, invalid, or over budget, a deterministic
  **catalog template** produces the same actions and prompts.
- Reports: terminal + `report.json` + `report.md` + `report.html`. **PDF later.**
- The current CLI look (colors, spinner, layout) is kept.

## The thread

```
vibeshield scan <github-url | local-folder>
  source.resolve        clone into sandbox  |  copy local folder in
  snapshot.manifest     small manifest: commit SHA, file list+hashes, exclusions, tool/DB versions
  inventory.detect      what's here (languages, manifests, workflows, IaC) — gates which checks run
  scan.*                run the checks inside the sandbox over the source:
                          secrets, code patterns, SBOM, dependencies, GitHub Actions, IaC
  findings.normalize    raw tool output -> Evidence -> Finding (+ semantic validators)
  findings.correlate    group findings with the same root cause
  actions.rank          ActionCandidate with rule-computed priority + verdict
  remediation.generate  ONE Opus 4.8 call: candidates -> explanation + prompt   (catalog fallback)
  report.compose        one SecurityAssessment object
  report.render         report.json / .md / .html + terminal (current CLI look)
```

Every stage runs from a single `StageRegistry` and records its attempt and its
output artifacts in SQLite + the blob store. Re-running marks downstream stages
stale and keeps old attempts.

## Build order

Iteration 1 is done when all three gates are closed. Each gate is closed by the
owner running the real command on a real repo — not by a passing test suite.

- **Gate 1 — the machine end to end, secrets only.**
  `vibeshield scan <repo>` on a real repo with a real planted secret runs the
  full thread with one check (secrets). The owner sees a verdict and one action
  naming the file/line, why it matters, and a copy-paste prompt (from the catalog
  template at this gate). Raw scanner output is saved as proof a real tool ran.
  Reliable structure (sandbox, registry/DAG, SQLite + blobs, resume) is real, not
  stubbed.
- **Gate 2 — all checks.** Add code patterns, SBOM, dependencies, GitHub Actions,
  and IaC behind the same registry/sandbox. Inapplicable checks are recorded as
  explicit skips. One check failing still yields a useful Fix Pack; lost required
  coverage yields `Scan incomplete`, never a green verdict.
- **Gate 3 — the AI fix-pack call.** Wire the one Opus 4.8 call to enrich the
  explanations and prompts, with the catalog fallback. The deterministic verdict,
  priority, and finding set must be identical whether the AI ran or not.

## Runtime

- One `SandboxRuntime` port: create, upload, exec, download, destroy, plus a
  network policy. The only adapter is `MicrosandboxRuntime`.
- One sandbox per run, created at source acquisition, reused across `scan.*`
  stages, destroyed at the end. Network is on.
- GitHub: `git clone --depth 1` inside the sandbox. Local: copy the folder in.
  The scanned app, package managers, build scripts, and git hooks are never
  executed — the checks only read the source.
- Scanners live in a plain Dockerfile-built image. Vulnerability databases update
  at the start of each run; the manifest records each tool's version and DB date.
  If an update fails (offline), the cached DB is used and freshness is marked
  degraded — a stale DB cannot support a green verdict.
- Offline / no-egress / pinned-image hardening is deferred (see "Later").

## Storage

```
~/.vibeshield/
├── state.sqlite                      source of truth: runs, stage attempts, artifacts,
│                                     findings, evidence, actions, events
├── blobs/sha256/<prefix>/<hash>      immutable raw artifacts (scanner outputs, redacted)
└── runs/<run-id>/                    regeneratable export/view, not the source of truth
    ├── manifest.json
    ├── report.json
    ├── report.md
    └── report.html
```

`state.sqlite` is authoritative; `runs/<id>/` can be fully rebuilt from it plus
the blob store. No source tarball is stored. Raw scanner output is redacted of
secret values before it enters the blob store.

## Module structure

Introduce the boundaries the thread needs; do not pre-create folders for unbuilt
stages. Domain code imports no sandbox, no SQLite, no filesystem paths, no env,
no renderers.

```
src/
  domain/        run, snapshot, stage, artifact, evidence, finding, remediation, assessment
  application/   scan-service, resume-service
  pipeline/      registry, planner, runner, validation
  stages/        source-resolve, snapshot, inventory, scanners, normalize, correlate, actions, remediation, report
  tools/         one thin adapter per scanner (argv, config, parse)
  agents/        pi remediation call
  ports/         sandbox-runtime, state-store, artifact-store, model-provider, event-sink
  adapters/      microsandbox, sqlite, filesystem-blobs, anthropic-model
  interfaces/    cli
  reporting/     terminal, markdown, html, json
```

## Contracts

Minimal on purpose — enough to keep stages coherent.

- **StageDefinition**: `id`, `version`, `dependencies`, `input artifacts`,
  `output artifacts`, `output schema`, `semantic validators`, `timeout`,
  `required` (does a failure block the run), `cache key`. The registry builds the
  DAG, validates dependencies/cycles, runs stages, emits progress, and marks
  descendants stale on rerun.
- **Manifest**: `origin` (url or path), `commit SHA` when available, `source
  hash` (over the canonical sorted file list, not the archive), `file list`
  (`path`, `size`, `sha256`), `exclusions` (`path`, `reason`), `tool versions`,
  `db dates`. Paths are POSIX-relative inside the repo; no absolute paths, `..`,
  NUL, or backslashes reach a check.
- **Data model**, separate levels so raw stays inspectable and the result stays
  clean:
  - `RawArtifact` — unmodified (redacted) tool output in the blob store.
  - `Evidence` — `id`, raw artifact ref, file path, line range, snippet (redacted),
    snippet hash, tool ref.
  - `Finding` — `id`, source tool, rule id, category, severity, confidence,
    locations, evidence ids, `fingerprint`, optional `remediation key`.
  - `FindingCluster` — same root cause: id, category, finding ids, max severity.
  - `ActionCandidate` — deterministic: id, remediation key, priority score,
    finding ids, evidence ids, affected files, verdict impact.
  - `RemediationAction` — the AI-or-catalog output for a candidate (below).
  - `SecurityAssessment` — the one result object: repository, manifest summary,
    toolchain (versions + DB dates), verdict, coverage (checked / skipped / failed
    / degraded with reasons), finding summary, ranked actions, and the limitation
    line: "This scan did not run your app; authorization logic and runtime
    behavior were not checked." All reports render from this object only.
- **Verdict** (rule-computed, before the AI call): `Critical fix needed`,
  `Not ready to deploy`, `Looks OK for now` (no blocking issues in covered
  checks), `Scan incomplete`. `Looks OK for now` requires the applicable required
  checks to have completed; failed/missing/stale required coverage →
  `Scan incomplete`. No absolute "safe" wording.
- **Ranking** uses only signals available now: tool severity, confidence, secret
  type, number of tools agreeing, direct vs transitive dependency, CI token
  permissions. Speculative signals (exposure, blast radius, reachability,
  production relevance) stay `unknown` — they are not guessed.
- **Remediation catalog** keyed by `remediation key` / rule id / category, each
  with: title, grouping key, base priority, why-it-matters, fix steps, verify
  steps, coding-agent prompt template. Unknown findings use a clearly-weaker
  generic template. The catalog is the deterministic fallback and the primary UX
  when the AI is off.
- **The one AI call** (`remediation.generate`, Claude Opus 4.8, high effort, via
  Pi, on the host):
  - Input: up to ten `ActionCandidate`s with their findings, redacted evidence
    snippets, affected files, the matching catalog entries, and the repo
    inventory.
  - Output per candidate: plain-language risk, why-fix-now, fix steps,
    operational steps, coding-agent prompt, verification.
  - Rules: use only the given finding/evidence ids; never change priority,
    severity, or verdict; return structured output; separate code changes from
    operational steps. One generation pass, one repair pass, then catalog
    fallback. Secret values are redacted out of the input.
- **Semantic validators** on stage outputs: referenced files exist in the
  snapshot, line ranges are in range, hashes match, ids resolve, paths stay
  inside the repo.
- **Secrets**: store secret type, file+line, masked preview, fingerprint, rule,
  and verification state. The full value never enters normalized data, reports,
  AI input, or the blob store.

## Resume

`resume <run>` re-runs missing, failed, and stale stages. `--from <stage>`
re-runs that stage and recomputes everything after it. `--only <stage>` re-runs
just that stage and marks everything after it stale. Old attempts are kept. State
is computed from SQLite, not from files on disk. Re-running a check re-acquires
the source (the sandbox is gone); if the commit moved, it is treated as a new
snapshot.

## Build discipline

Forward rules; a reviewer rejects work that breaks one.

- Check output comes only from running a real tool. No module fabricates,
  simulates, or heuristically generates tool output on the product path.
- The owner closes each gate by running the real command on a real repo. Passing
  tests is necessary, never sufficient.
- Build gate by gate; do not scaffold a later gate's needs early. Keep files
  small; a large file is a signal to stop, not progress.

## Current codebase

The working tree is the old MVP (Pi mapping agents and an `attack-hypotheses`
stage running through Daytona). Iteration 1 replaces that default path.

- Keep the CLI presentation in `src/cli/run-cli.ts` (palette, spinner, layout) —
  reuse the visual primitives; the help/summary content changes to the new flow.
- Update the README to this product (Quick Scan, Agent Fix Pack, GitHub-URL or
  local-folder input, the verdicts, the no-runtime-validation limitation).
- Remove as the new path lands: Daytona; OpenRouter as a required dependency; Pi
  section/mapping collectors and per-area agent loops; `attack-hypotheses`;
  evaluator/self-reflection loops; repository-map-as-pipeline-truth; duplicate
  stage-order arrays; mutable-path artifact overwrite; the in-memory artifact
  registry. Keep Pi only as the harness for the one remediation call.

## Later — named, not dropped

- AI hypotheses + verification loop (the second AI stage).
- Deeper code analysis / evidence graph (cdxgen + atom, Joern/codebadger) — rides
  with hypotheses.
- Richer scoring (exposure, blast radius, reachability, production relevance).
- Offline / no-egress isolation + a pinned, published toolchain image and the
  build/update/storage infra it needs.
- PDF report; private GitHub repos; zip upload; `doctor` / `runtime` / `tools`
  commands.
- SaaS: Postgres + object storage behind the same state/artifact ports; web UI.

## Open

- Which real repo proves Gate 1 — ideally the owner's own project with a planted
  test secret, so usefulness is visible from the first run.
