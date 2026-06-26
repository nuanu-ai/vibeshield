# Architecture

VibeShield is a local security-audit CLI for AI-generated and beginner-built web
projects. It accepts either a public GitHub repository URL or a local Git
worktree root and returns a small, inspectable **Agent Fix Pack**: concrete
findings, file/line evidence, plain-language explanation, and prompts the owner
can paste into a coding agent.

There are two product modes:

- **Quick Scan**: `vibeshield scan <github-url-or-local-git-root>`. This is the
  default, deterministic scanner pipeline.
- **Deep Static**: `vibeshield scan <repo> --deep`. This runs Quick Scan, then
  adds a Joern-backed security graph, static attack hypotheses, validation
  recipes, and richer report sections.

The model is never the source of truth. Scanners, graph facts, priorities,
verdicts, coverage, and hypothesis statuses are deterministic before any model
call. Optional OpenRouter calls only improve wording and coding-agent prompts.

## Runtime Boundary

Repositories scanned by VibeShield are untrusted input.

The default runtime creates one fresh Microsandbox per scan. GitHub input is
cloned inside the sandbox. Local input must be a Git worktree root; the host
creates a Git-filtered archive, uploads it, and extracts it inside the sandbox.

The host orchestrates the run, stores artifacts, renders reports, and performs
optional model calls. Scanner tools and Joern run inside the sandbox, never on
the host. VibeShield does not start the scanned app and does not run package
scripts, tests, builds, migrations, app commands, or git hooks from the scanned
repository.

Network is enabled for the current product slice. Scanner vulnerability data is
refreshed at run start where the toolchain supports it, and freshness is
recorded in the manifest. If the sandbox or toolchain is unavailable, the scan
fails clearly instead of falling back to host execution.

## Run State

The default state root is `~/.vibeshield`:

- `runs/<run-id>/` contains owner-facing run artifacts such as `manifest.json`,
  `report.json`, `report.md`, `report.html`, and, for Deep Static,
  `repository-map.json`;
- `state.sqlite` records runs, stage attempts, artifact refs, SecurityGraph
  projections, and Deep Static coverage;
- `blobs/sha256/...` stores content-addressed raw artifacts, including redacted
  scanner outputs and Joern program-analysis artifacts.

The run id is the identity for both Quick Scan and Deep Static. Deep Static adds
stages and artifacts to the same run; it does not create a second pipeline or a
second source of truth.

The state model is resume-shaped, but CLI resume is not available yet:
`vibeshield resume` fails clearly. Old MVP surfaces and old run contracts are
not compatibility targets.

## Quick Scan Flow

```text
vibeshield scan <github-url-or-local-git-root>
  -> source.resolve
       GitHub: clone inside Microsandbox
       local: upload Git-filtered snapshot into Microsandbox
  -> toolchain.refresh
       refresh scanner vulnerability databases where applicable
  -> snapshot.manifest
       origin, commit when available, file hashes, exclusions, tool/DB versions
  -> inventory.detect
       languages, package manifests, workflows, IaC/config files
  -> scan.*
       gitleaks
       opengrep
       syft
       trivy vuln
       osv
       actionlint
       zizmor
       trivy config
  -> findings.normalize
       redacted raw artifacts -> Evidence -> Finding
  -> findings.correlate
       cluster same-root-cause findings
  -> actions.rank
       deterministic priority, verdict impact, and verdict
  -> remediation.generate
       catalog remediation for every action
       optional bounded OpenRouter calls per action
  -> report.compose
       one SecurityAssessment
  -> report render
       terminal receipt + report.json + report.md + report.html
  -> destroy sandbox
```

The implemented Quick Scan check stages are:

| Check | Tool | Runs When | Purpose |
| --- | --- | --- | --- |
| `secrets.gitleaks` | `gitleaks` | Always | Detect committed secret-like values. |
| `code-patterns.opengrep` | `opengrep` | Source files exist | Detect simple unsafe code patterns. |
| `sbom.syft` | `syft` | Dependency manifests exist | Produce a CycloneDX SBOM artifact. |
| `dependencies.trivy` | `trivy fs --scanners vuln` | Dependency manifests exist | Detect vulnerable dependencies from the SBOM/filesystem view. |
| `dependencies.osv` | `vibeshield-osv-scan` | Dependency manifests exist | Detect vulnerable packages with OSV data. |
| `github-actions.actionlint` | `actionlint` | Workflow files exist | Parse and lint GitHub Actions workflows. |
| `github-actions.zizmor` | `zizmor` | Workflow files exist | Detect GitHub Actions hardening issues. |
| `iac.trivy-config` | `trivy config` | IaC/config files exist | Detect infrastructure/config issues. |

That is eight check stages backed by seven scanner binaries because `trivy` is
used for both dependency and IaC checks.

## Deep Static Flow

Deep Static is opt-in and runs after the direct scanner facts exist:

```text
vibeshield scan <repo> --deep
  -> Quick Scan stages through actions.rank
  -> deep.static.compose
       quick.graph-import
       program-analysis.model       Joern builds the CPG/IR
       program-analysis.extract     entities, boundaries, calls, flows, usage
       security-graph.compose       one deterministic SecurityGraph projection
       graph.context                CI/IaC, content/assets, smart contracts
       graph.reachability           component/dependency usage context
       graph.correlate              deterministic hypothesis candidates
       hypotheses.static-validate   supported / contradicted / inconclusive
       validation-recipes.compose   concrete runtime check recipes
       repository-map.render        derived human graph view
  -> remediation.generate           Quick Scan action wording
  -> hypotheses.enrich              optional bounded model batches for hypotheses
  -> report.compose
  -> report render
```

Deep Static keeps direct findings and attack hypotheses separate:

- a direct finding is scanner-backed evidence, such as a published secret or a
  vulnerable package;
- a static hypothesis is a graph-backed path the owner should validate, such as
  external input reaching a dangerous operation;
- `deepActionGroups` group direct actions and linked hypotheses only when that
  avoids duplicate work for the owner.

Deep Static can strengthen the verdict to `not-ready-to-deploy` when at least
one hypothesis is `statically_supported`. It does not rewrite Quick Scan
findings, severities, fingerprints, or direct evidence.

## Program Analysis Backend

Joern is the only production program-analysis backend. There is no secondary
program-analysis fallback and no legacy compatibility layer for old
program-analysis contracts.

The backend interface is language-agnostic above the implementation, but the
current Joern backend selects one supported language for the source snapshot:
JavaScript, TypeScript, Java, Python, or Go. Unsupported source files are
reported through `language_support` coverage. Mixed-language repositories can be
partially covered; the report must say which coverage area is partial,
degraded, failed, or skipped.

Joern produces two artifact classes:

- a raw program model artifact, stored as `program-analysis.raw`;
- normalized slice artifacts, stored as `program-analysis.slice`.

VibeShield owns the extraction scripts, normalization, graph composition, and
hypothesis rules above Joern. Joern is the static-analysis engine, not the
product policy engine.

## Security Graph

`SecurityGraph` is the source of truth for Deep Static correlation. The full
Joern CPG/IR remains a blob artifact; the graph is the compact deterministic
projection later stages use for validation and reports.

Graph nodes include:

- boundaries, code entities, sources, sinks, controls, flows;
- components, findings, secrets, build steps, infrastructure resources,
  external services, data stores, and content/resources.

Graph edges include:

- containment/import/call/registration relationships;
- receives/flows-to/uses/reads/writes relationships;
- protection, exposure, dependency, location, impact, support, and contradiction
  relationships.

Stable ids come from content such as repository path, symbol, line range, node
kind, edge kind, and graph version. Backend-assigned ids do not become product
ids. The same snapshot should produce the same graph, hypotheses, ids, and
ordering.

`repository-map.json` is derived from `SecurityGraph` for humans and debugging.
It is not the pipeline source of truth.

## Hypotheses

Deep Static currently emits deterministic candidate families for:

- external input to dangerous operation;
- Quick SAST finding to reachable path;
- dependency vulnerability to usage path;
- CI supply-chain path;
- secret impact chain;
- hidden content/resource exposure;
- smart-contract risk.

Static hypothesis statuses are intentionally limited:

- `candidate`;
- `statically_supported`;
- `statically_contradicted`;
- `inconclusive`.

`confirmed` is reserved for a future runtime-validation stage. Current reports
must say "not observed on the analyzed path" rather than claiming a control is
globally absent.

## Model Calls

Model calls are enhancement-only and batch-bounded:

- Quick Scan remediation starts with catalog text for every ranked action, then
  sends at most the top bounded actions to OpenRouter one action at a time with
  limited concurrency.
- Deep Static hypothesis enrichment starts with catalog text for every
  hypothesis, then sends hypothesis batches with bounded batch size and
  concurrency.
- If a model call is unavailable, invalid, slow, or fails, only that action or
  hypothesis falls back to catalog text.
- Model output is schema-validated and cannot change ids, paths, line numbers,
  findings, graph refs, statuses, priorities, verdicts, or coverage.

The deterministic result is complete without `OPENROUTER_API_KEY`.

## Progress And Terminal Output

The terminal is owner-facing, not a raw sandbox log. Stages emit structured
events; the terminal maps them to friendly labels such as "Running security
checks", "Running Deep Static analysis", "Tracing data flow", and "Explaining
likely attack paths".

On TTY streams the terminal uses a spinner for the current progress label. On
non-TTY streams it prints each deduplicated label once. Raw sandbox stderr/stdout
can be counted and recorded as event details, but raw Joern or scanner output is
not printed directly as user-facing CLI text.

## Coverage And Verdict

Quick Scan coverage states are:

- `checked`: the applicable tool ran and produced parseable output;
- `skipped`: the check was not applicable to this repository;
- `failed`: the tool or parser failed;
- `degraded`: supporting data such as vulnerability DB freshness is stale or
  incomplete.

Deep Static adds `partial` for graph and program-analysis areas where the
backend observed some but not all relevant facts. Important Deep Static coverage
areas include language support, entities, boundaries, call graph, data flow,
dependency usage, CI/IaC, content assets, and smart contracts.

Required Quick Scan coverage loss blocks a green verdict. Deep Static coverage
loss is surfaced in the report and limitations instead of pretending the graph
is complete. Other completed checks still produce a useful Fix Pack.

## Reports

The terminal ends with a short receipt: repository, verdict, report path, and the
static-scan limitation. Full details live in `report.html` and `report.md`.

`report.json` is the machine-readable `SecurityAssessment`. It includes the
manifest summary, repository identity, toolchain summary, Quick Scan coverage,
Deep Static coverage when present, evidence, findings, clusters, ranked actions,
static hypotheses, validation recipes, hypothesis enrichments, deep action
groups, verdict, and limitations.

Raw scanner outputs are redacted before entering blob storage. The scanned
source tree itself is not stored as a run artifact. The manifest is the
reproducibility boundary: origin, commit SHA when available, file list, hashes,
exclusions, source hash, tool versions, and DB freshness.

## Benchmarks

`docs/benchmark-methodology.md` is the quality measurement contract for the R&D
path: Phase 1 proves capability against curated external truth, and Phase 2
optimizes cost, latency, and stack size without dropping below the same metric
floor. It defines the scored surfaces, ground-truth rules, precision/recall
targets, anti-overfit discipline, baseline procedure, and gap-driven R&D work
order.

`docs/deep-static-training-benchmark.md` is the current regression gate for the
Joern-backed Deep Static pipeline. It is an input to the methodology, not the
full scored TP/FP/FN harness yet. The checked matrix covers:

- WebGoat (Java);
- Juice Shop (JS/TS);
- Freeland (local JS/TS);
- Vulnerable-Flask-App (Python);
- go-dvwa (Go).

The benchmark asserts machine-readable candidate families, supported static
hypotheses, no failed Deep Static coverage, complete dependency-usage coverage
where dependency components exist, and curated ground-truth expectations for
WebGoat and Juice Shop. Python and Go scored precision/recall require pinned
curated truth for Vulnerable-Flask-App and go-dvwa first. Freeland is a local
stability and determinism canary, not a precision/recall source.

Benchmark repositories are product benchmarks, not training patches: failures
should expose systemic gaps in Joern extraction, graph construction, rule
taxonomy, validation logic, or reporting.

Do not add repository-specific detector behavior to make benchmark runs pass.

## Retired Surfaces

The current architecture does not include Daytona, Pi mapping collectors,
repository-map-as-truth, attack-hypothesis evaluator loops, in-memory run
registries, host-executed scanners, non-Git local directory fallback, or
compatibility shims for old run contracts.
