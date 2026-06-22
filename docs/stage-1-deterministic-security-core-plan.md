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
- The one AI call uses **Claude Opus 4.8 (high reasoning effort)** via Pi over
  **OpenRouter** (the model gateway, as in the current codebase), **on the host**
  (it needs the findings, not the repo). It is **enhancement only** — the
  deterministic result is complete without any model.
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

## Implementation tasks

Grouped by gate. Each task is meant to be opened alone — Inputs / Do / Outputs /
Done. Contracts referenced here are defined in "Contracts" below. A gate closes
when the owner runs the real command on a real repo and sees its result — not
when tests pass. Iteration 1 is done when all three gates close.

### Gate 1 — the whole machine end to end, secrets check only

Closes when: `vibeshield scan <real-repo-with-a-planted-secret>` shows a verdict
and one usable action (file/line, why, paste-ready prompt from the catalog), with
the raw scanner output saved as proof a real tool ran.

Status:

- [x] **Gate 1 acceptance.** A live local planted-secret scan ran in
  Microsandbox, produced `Critical fix needed`, included `src/config.ts:4`, wrote
  redacted raw gitleaks output + `manifest.json` / `report.json` / `report.md` /
  `report.html`, and destroyed the sandbox. A public GitHub URL smoke also
  reached source acquisition, manifest, scan, and report.

- [x] **Backbone + ports.** In: current TS package. Do: add `domain` contracts
  (Run, Stage, Artifact, Evidence, Finding, ActionCandidate, RemediationAction,
  SecurityAssessment), a `ScanService`, and the ports (sandbox-runtime,
  state-store, artifact-store, model-provider, event-sink); domain imports no
  adapter. Out: a typed skeleton the thread flows through. Done: a scan call goes
  CLI → ScanService → registry → ports with no domain→adapter import.
- [x] **MicrosandboxRuntime.** In: the SandboxRuntime port. Do: implement
  create/upload/exec/download/destroy with network on; a fake runtime for tests.
  Out: production adapter + fake. Done: a trusted command runs in a real sandbox,
  writes a file, downloads it, sandbox destroyed; unsupported host fails clearly.
- [x] **State store (SQLite) + blob store.** In: state root (default
  `~/.vibeshield`, test-overridable). Do: the tables and `blobs/sha256/...`;
  identical bytes reuse one blob; rerun adds a new attempt, never overwrites. Out:
  persisted state + regeneratable `runs/<id>/` export. Done: one run shows rows +
  blob refs; rerun adds an attempt.
- [x] **Stage registry + runner.** In: stage definitions. Do: register,
  build/validate the DAG, run, record attempts/events. Out: the DAG drives the
  thread. Done: stage list comes from the registry and every stage attempt is
  persisted.
- [x] **Source acquisition.** In: GitHub URL or local folder. Do: GitHub →
  `git clone --depth 1` inside the sandbox; local → copy in; `.git` present → drop
  ignored files and read the commit SHA, else a default ignore set. Out: a source
  dir in the sandbox. Done: ignored files excluded; URL and folder both reach a
  source dir.
- [x] **Snapshot manifest.** In: the source dir. Do: write the manifest (commit
  SHA, file list+hashes, exclusions, source hash, tool+DB versions). Out:
  `manifest.json`. Done: same input → same source hash; no source tarball stored.
- [x] **Secrets check adapter (gitleaks).** In: source dir in the sandbox. Do: run
  gitleaks (argv, fixed config, timeout); redact secret values; store the redacted
  raw output as a blob. Out: `RedactedRawArtifact` + finding candidates. Done: a
  planted secret is
  found; raw output present and redacted.
- [x] **Normalize → Evidence → Finding.** In: candidates. Do: build Evidence and
  Finding per the data model; run semantic validators; collapse duplicates. Out:
  findings + evidence in SQLite. Done: a finding pointing outside the snapshot is
  rejected.
- [x] **Actions + ranking + verdict (deterministic).** In: findings. Do: group by
  remediation key, score with the ranking signals, compute the verdict — all
  before any AI. Out: `ActionCandidate`s + verdict. Done: rank order is
  explainable from visible fields; a live secret → `Critical fix needed`.
- [x] **Catalog remediation + report.** In: candidates + catalog. Do: fill catalog
  templates into `RemediationAction`s; compose one `SecurityAssessment`; render
  terminal/json/md/html through the kept CLI look. Out: `report.json/.md/.html`.
  Done: closes Gate 1.

### Gate 2 — all checks

Closes when: a fixture matrix touching every check shows a coverage table and a
still-useful Fix Pack when one check is killed.

Status:

- [x] **Gate 2 acceptance.** Live Microsandbox fixture matrix ran. Run
  `20260622131315-4a83541f` used `vibeshield-toolchain:gate2-check` and showed
  all checks `checked` with an IaC Fix Pack action for `Dockerfile:1`. Run
  `20260622131504-b50e4eef` used a derived image without `actionlint`, recorded
  `github-actions.actionlint: failed`, kept `Critical fix needed`, and produced
  separate Fix Pack actions for `src/config.ts:2` and `Dockerfile:1`. Follow-up
  run `20260622133434-84911c56` verified the hardened runtime contract: manifest
  image tag `vibeshield-toolchain:gate2-check`, Trivy DB date recorded with
  `dbStale: false`, all applicable checks `checked`, and separate Fix Pack
  actions for secret, dependency, and IaC findings.

- [x] **Inventory.detect.** In: manifest. Do: detect languages, manifests,
  workflows, IaC to gate which checks apply. Out: a scan plan. Done: a repo with
  no workflows skips the Actions checks with a recorded reason.
- [x] **Remaining check adapters.** In: source dir. Do: thin adapters
  (argv/config/parse) for code patterns (opengrep), SBOM (syft), dependencies
  (trivy), GitHub Actions (actionlint + zizmor), IaC (trivy config); vuln DBs
  refresh at run start. Out: raw artifacts + candidates per tool. Done: each
  applicable check runs or records a skip reason.
- [x] **Correlate + degradation.** In: findings from all checks. Do: cluster
  same-root-cause findings; one failing check still yields a Fix Pack; lost
  required coverage → `Scan incomplete`. Out: clusters + truthful coverage. Done:
  killing one check keeps other findings; required-coverage loss blocks green.

### Gate 3 — the one AI fix-pack call

Closes when: the verdict, priority, and finding set are identical with the AI on
vs off; the AI only makes the explanations and prompts read better.

- [ ] **Model provider (OpenRouter / Opus 4.8).** In: model-provider port. Do:
  OpenRouter adapter calling Claude Opus 4.8 (high effort); key from env; absent
  key → catalog fallback, not a crash. Out: a model client. Done: a call returns
  structured output; missing key degrades cleanly.
- [ ] **remediation.generate + fallback.** In: ≤10 candidates + findings +
  redacted snippets + catalog + inventory. Do: **one** Opus 4.8 call producing
  per-candidate explanation/steps/prompt/verify; validate ids/paths; invalid →
  catalog (no repair). Out: enriched `RemediationAction`s. Done: closes Gate 3.

### Cross-cutting (alongside the gates)

- [ ] **CLI look + README.** Keep the `run-cli.ts` palette/spinner; rewire the
  content to the new flow; rewrite the README to this product. Done: owner
  confirms the output keeps the tuned look and the README matches `scan`.
- [ ] **Minimal resume.** In: a run id or run directory. Do: re-run
  missing/failed/stale stages and mark descendants stale on forced rerun. Out:
  resume reuses durable state instead of starting from scratch. Done: resume
  re-runs only stale/failed/missing work.
- [ ] **Remove old MVP** as each replacement lands: Daytona, Pi mapping
  collectors, `attack-hypotheses`, evaluator loops, repo-map-as-truth, duplicate
  stage arrays, mutable-path overwrite, in-memory registry. Keep Pi + OpenRouter
  as the harness/gateway for the one remediation call.

## Runtime

- One `SandboxRuntime` port: create, upload, exec, download, destroy, plus a
  network policy. The only adapter is `MicrosandboxRuntime`.
- One sandbox per run, created at source acquisition, reused across `scan.*`
  stages, destroyed at the end. Network is on.
- GitHub: `git clone --depth 1` inside the sandbox. Local: copy the folder in.
  The scanned app, package managers, build scripts, and git hooks are never
  executed — the checks only read the source.
- **Toolchain image.** A `toolchain/Dockerfile` installs the scanners. Build it
  **once** into a local image tagged `vibeshield-toolchain` (a documented build
  command; or `scan` builds it the first time if it is missing, with Docker or
  podman). Microsandbox boots that image by tag. Scanners never run on the host;
  if the image is missing and cannot be built, `scan` stops with a clear message.
  Updating tool versions and rebuild policy are decided later. The image tag is
  recorded in the manifest.
- **Order inside the sandbox:** create → acquire source (clone/copy) → refresh
  vulnerability DBs → run checks → collect outputs → destroy. The DB updaters are
  fixed trusted commands that do not read repository content, so updater traffic
  and untrusted repo data never mix. The manifest records each tool's version and
  DB date; a failed update falls back to the cached DB and marks freshness
  degraded — a stale DB cannot support a green verdict.
- **Egress (iteration 1):** the sandbox has unrestricted network — accepted per
  the locked decisions. An egress allowlist and an offline pinned image are the
  isolation/SaaS hardening track, not iteration 1.

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
  adapters/      microsandbox, sqlite, filesystem-blobs, openrouter-model
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
- **Source filtering** (what reaches a check): with `.git`, exclude git-ignored
  files; without `.git`, apply a built-in ignore set (`.git`, `node_modules`,
  `dist`, `build`, `.next`, `out`, `target`, `vendor`, `.venv`/`venv`,
  `__pycache__`, `.cache`, coverage/output dirs). Exception: `.env` / `.env.*` are
  always included even if ignored — finding a real key is the point. Limits: skip
  files over 5 MB, stop past 50k files or 500 MB total, each recorded as a
  `too_large` / `truncated` exclusion. Never follow a symlink resolving outside
  the source root. Every exclusion is in the manifest with a reason.
- **Data model**, separate levels so raw stays inspectable and the result stays
  clean:
  - `RedactedRawArtifact` — the tool's own output, format preserved, secret values
    masked, nothing else changed; stored in the blob store.
  - `Evidence` — `id`, redacted-raw-artifact ref, file path, line range, snippet
    (redacted), snippet hash, tool ref.
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
- **The one AI call** (`remediation.generate`): Claude Opus 4.8, high reasoning
  effort, via Pi over OpenRouter, on the host. The OpenRouter key comes from an
  env var; if it is missing, the call is skipped and the catalog is used.
  - Input: up to ten `ActionCandidate`s with their findings, redacted evidence
    snippets, affected files, the matching catalog entries, and the repo
    inventory.
  - Output (structured JSON against the `RemediationAction` schema) per candidate:
    plain-language risk, why-fix-now, fix steps, operational steps, coding-agent
    prompt, verification.
  - Rules: use only the given finding/evidence ids; never change priority,
    severity, or verdict; separate code changes from operational steps. Secret
    values are redacted out of the input.
  - **Exactly one model call.** Its output is validated (schema + semantic
    validators). Anything that fails validation falls back to the catalog for that
    candidate — no repair step.
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
the source (the sandbox is gone) and recomputes the source hash. Equal to the
recorded manifest hash → the run continues on the same snapshot. Different — a
moved GitHub commit, or edited local files — → it is a **new snapshot**: a fresh
run starts and the owner is told the source changed, so resume never silently
scans different bytes under the old run's identity.

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
- Remove as the new path lands: Daytona; Pi section/mapping collectors and
  per-area agent loops; `attack-hypotheses`; evaluator/self-reflection loops;
  repository-map-as-pipeline-truth; duplicate stage-order arrays; mutable-path
  artifact overwrite; the in-memory artifact registry. Keep Pi and OpenRouter as
  the harness/gateway for the one remediation call — no model is required for the
  deterministic result.

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
