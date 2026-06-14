# Architecture

VibeShield is a local CLI pipeline that accepts a GitHub repository URL and
returns an inspectable run directory. The current product slice produces repository
understanding artifacts, not a security verdict.

Repository-map intent and section expectations are defined in
`docs/repository-map-expectations.md`. Architecture should preserve that product
boundary: facts-only map first, later threat modeling/manual review second.

## Runtime Boundary

Repositories scanned by VibeShield are untrusted input.

The default runtime creates a fresh Daytona sandbox for each scan, clones the
target repository inside the sandbox, runs scanner and Pi jobs there, pulls only
expected artifacts back to the local run directory, and deletes the sandbox at
the end.

The local host is responsible for orchestration, artifact storage, reports, and
tests. It must not clone or execute the scanned repository directly when live
credentials are available.

## End-To-End Flow

```text
vibeshield scan <github-url>
  -> validate GitHub URL
  -> create fresh Daytona sandbox
  -> clone repo inside sandbox
  -> generate inventory inside sandbox
  -> pull inventory artifact locally

  -> deterministic baseline
       -> prepare/probe scanner tools
       -> syft SBOM
       -> trivy scan from SBOM
       -> gitleaks
       -> actionlint, if GitHub Actions exist
       -> zizmor, if GitHub Actions exist
       -> checkov, if IaC/config candidates exist
       -> baseline-summary.json

  -> build Pi context pack
       -> compact repo/inventory facts
       -> neutral repository navigation index
       -> no raw scanner output/debug noise

  -> facts-only AppSec repository map
       -> deterministic coverage-structure from inventory
       -> Pi collector: stack-build-deps
       -> Pi collector: entrypoints
       -> Pi collector: config-secrets
       -> Pi collector: auth-access
            input: entrypoints + config-secrets
       -> Pi collector: storage-data-model
       -> Pi collector: external-integrations-egress
            input: config-secrets
       -> Pi collector: infra-deploy
       -> Pi collector: operation-sinks
       -> Pi collector: crypto
       -> Pi collector: logging-observability
       -> Pi collector: data-flows
            input: entrypoints + operation-sinks
       -> Pi collector: trust-boundaries
            input: prior map artifacts
       -> Pi synthesis: repository-map
            input: all section artifacts

  -> write report.md
  -> write run.json/events.jsonl
  -> delete Daytona sandbox
```

## Deterministic Baseline

Baseline scanners run before Pi and provide normalized context for later
analysis. A scanner failure does not stop the whole baseline step. Each tool
records status, invocation metadata, diagnostics, artifacts, and any concrete
findings that can be normalized from its output.

Current baseline tools:

- `syft`: CycloneDX SBOM generation.
- `trivy sbom`: vulnerability observations from SBOM input.
- `gitleaks`: secret observations.
- `actionlint`: conditional on GitHub Actions workflows.
- `zizmor`: conditional on GitHub Actions workflows.
- `checkov`: conditional on IaC/config candidates.

`osv-scanner` is deferred until its Daytona/network behavior is reliable enough
for the sandboxed scan pipeline.

Concrete deterministic findings are written to `baseline-summary.json` and
shown directly in `report.md`; raw scanner output remains available under
`outputs/baseline/<tool>/`.

## Pi Context Pack

`StepContextBuilder` creates `outputs/pi-context-pack.json` from validated
artifacts. It keeps Pi input compact and excludes raw scanner output, logs,
debug metadata, and high-volume diagnostics.

The source context pack includes:

- repository URL and commit SHA;
- inventory summaries, language/LOC summary, top-level directories, manifests,
  package/lock files, generic config/infra files, and grouped source index;
- baseline-derived IaC paths.

Each Pi collector receives a smaller per-step projection of this source context:

- `stack-build-deps`: repo identity, language summary, manifest/package/lock
  files, CI/IaC, generic config, and infra paths;
- `entrypoints`: repo identity, compact structure signal, and grouped source
  index;
- `config-secrets`: repo identity, generic config files, manifests, top-level
  directories, and grouped source index needed to identify config/secret
  reference facts;
- `auth-access`: repo identity, accepted entrypoints, accepted config-secrets,
  and grouped source index needed to identify auth/access-control facts;
- `storage-data-model`: repo identity, manifests, accepted config-secrets, and
  grouped source index focused on schemas, models, migrations, and storage
  declarations;
- `external-integrations-egress`: repo identity, accepted config-secrets,
  manifests, and grouped source index focused on clients, SDKs, hosts, and
  brokers;
- `infra-deploy`: repo identity, infra files, IaC candidates, CI workflow paths,
  generic config files, and top-level directories;
- `operation-sinks`: repo identity and grouped source index focused on
  operation families;
- `crypto`: repo identity, grouped source index, and config files where
  TLS/crypto settings may be declared;
- `logging-observability`: repo identity, grouped source index, manifests, and
  config files for logger/telemetry destinations;
- `data-flows`: accepted entrypoints and accepted operation sinks;
- `trust-boundaries`: accepted prior map artifacts only.

## Repository Map Pipeline

The repository map pipeline produces facts-only AppSec artifacts as described in
`docs/repository-map-expectations.md`. These artifacts are not a security review
and not a full program trace; they are a compact, evidence-backed navigation map
for later analysis and threat modeling.

The current implementation builds coverage deterministically from inventory, then
calls Pi once per remaining map step. A complete successful scan runs one
deterministic coverage job plus thirteen Pi jobs:

- `coverage-structure`: deterministic inventory projection for repository size,
  language LOC, repository shape, inventory-covered directories, excluded
  directories, access gaps, and fact gaps. This covers original map sections 0
  and 2.
- `stack-build-deps`: collect languages, frameworks, runtimes, package
  managers, manifests, lockfiles, direct dependency signals, declared build
  commands, CI evidence, and vendored/lockfile facts. This covers original map
  sections 1 and 11.
- `entrypoints`: collect externally reachable or externally triggered
  boundaries such as HTTP routes, CLI commands, events, webhooks, scheduled
  jobs, uploads, and parsers. This covers original map section 3.
- `config-secrets`: collect config loading, env variables, config files,
  defaults/examples, secret-manager references, and redacted secret-like
  reference locations at configuration-source level. This covers original map
  section 7.
- `auth-access`: collect authentication/authorization mechanisms, middleware,
  guards, role/scope checks, session/token storage or checks, and observable
  protected/public/unknown status for accepted entrypoints without
  rediscovering entrypoints. This covers original map section 4.
- `storage-data-model`: collect DB/storage/schema/cache/queue facts and data
  model field names. This covers original map section 9.
- `external-integrations-egress`: collect third-party APIs, SDKs, outbound
  hosts, configured service URLs, and brokers. This covers original map section
  10.
- `infra-deploy`: collect Docker, compose, Kubernetes, IaC, proxy, hosting,
  runtime, and deploy declarations. This covers original map section 12.
- `operation-sinks`: collect observable operation sinks such as DB queries,
  process execution, filesystem/path operations, parsing/deserialization,
  redirects, and outbound URL/client construction. This covers original map
  section 6.
- `crypto`: collect observable crypto, randomness, password hashing, and TLS
  configuration facts. This covers original map section 8.
- `logging-observability`: collect logging/telemetry call sites, logged field
  names, and configured destinations. This covers original map section 13.
- `data-flows`: use only the accepted `entrypoints` and `operation-sinks`
  artifacts to record bounded shallow paths from
  external input to operation sinks. This covers original map section 5.
- `trust-boundaries`: synthesize inference-only trust boundaries from prior map
  artifacts; it must reference existing IDs/evidence instead of rediscovering
  repository facts. This covers original map section 14.
- `repository-map`: synthesize the final human-oriented repository map from all
  section artifacts; it must not add new facts.

Each Pi job writes a structured JSON artifact. Dependent jobs receive the
minimal context or prior artifacts they need, so Pi does not carry one large
prompt across the whole repository.

## Pi Quality Gate

The current pipeline uses a single Pi collector pass per map section:

```text
collector Pi
  -> section JSON
  -> schema-only validation
  -> write final artifact
```

The deterministic validator only checks JSON/schema/shape. It does not enforce
semantic correctness, evidence correctness, output budgets, or reviewer-quality
judgment.

There is no semantic evaluator loop in the current implementation. A Pi job is:
collector run -> deterministic validation -> accepted artifact or failed run.

The collector is the exploration role. It runs with read/search/list tools and
must do the section-specific discovery work before returning section JSON. It
stays at map level: repository structure, boundary declarations/registrations,
auth/config facts, observable operation lines, storage/data model facts,
integration facts, infra/deploy facts, crypto/logging facts, and bounded
external-input connections. Internal critical operations without an
observable external input source remain in operation sinks, coverage, or fact
gaps rather than invented flows. Trust boundaries are explicitly marked as
inferences and may only reference facts and IDs from earlier artifacts.

## Pi Runtime Observability

Live Pi jobs run through the Daytona runtime in Pi `--mode json`. VibeShield
does not print raw Pi output, thinking, tool arguments, or tool results to the
CLI. The sandbox runner filters Pi JSONL events into compact lifecycle messages
and streams only those sanitized events back to the host:

- runner start;
- `thinking...` when the agent starts a reasoning turn;
- one event per completed tool call, with tool name and a compact path/pattern
  when Pi exposes one;
- periodic heartbeat while Pi is still running;
- output start and completion/failure.

The final structured artifact is reconstructed from the final assistant text
and written to `outputs/pi/<stage>/<stage>.raw.redacted.txt`. The raw Pi JSONL
event stream is not stored as a user artifact.

Progress messages label the running Pi mapping job as the stage `collector`.

## Artifacts

Successful runs write inspectable artifacts under the local run directory:

- `outputs/inventory.json`
- `outputs/baseline/tool-availability.json`
- `outputs/baseline/syft-sbom.json`
- `outputs/baseline-summary.json`
- `outputs/pi-context-pack.json`
- `outputs/repo-map/coverage-structure.json`
- `outputs/repo-map/stack-build-deps.json`
- `outputs/repo-map/entrypoints.json`
- `outputs/repo-map/auth-access.json`
- `outputs/repo-map/config-secrets.json`
- `outputs/repo-map/storage-data-model.json`
- `outputs/repo-map/external-integrations-egress.json`
- `outputs/repo-map/infra-deploy.json`
- `outputs/repo-map/operation-sinks.json`
- `outputs/repo-map/crypto.json`
- `outputs/repo-map/logging-observability.json`
- `outputs/repo-map/data-flows.json`
- `outputs/repo-map/trust-boundaries.json`
- `outputs/repository-map.json`
- `outputs/pi/<stage>/...` raw/stderr/progress/metadata artifacts
- `report.md`
- `run.json`
- `events.jsonl`

## Failure Semantics

Failures after sandbox creation should leave a useful run directory:

- `run.json.status = "failed"`;
- failed stage and user-facing reason;
- redacted diagnostics;
- partial artifacts where available;
- sandbox cleanup result;
- non-zero CLI exit code.

The sandbox should be deleted after both success and failure.

## Resume Semantics

`vibeshield resume <run-dir>` continues a failed run from durable local
artifacts. Final accepted artifacts are reused; raw Pi candidates are not
treated as accepted output.

Resume always creates a fresh sandbox and clones the original repository at the
`commit_sha` recorded in `run.json`. If the run records a previous sandbox id,
VibeShield first asks the sandbox provider to delete that old sandbox id. A
failed, unsupported, or not-found stale-sandbox cleanup is recorded in
`events.jsonl` but does not block the fresh resume sandbox.

The resume boundary is artifact-based:

- reuse `inventory` when present, otherwise rebuild inventory;
- reuse `baseline-summary` when present, otherwise rerun deterministic
  baseline;
- reuse `pi-context-pack` when present, otherwise rebuild context;
- resume Pi from the first missing final map artifact in the section order from
  `coverage-structure` through `repository-map`;
- rewrite `report.md` from the final accepted artifacts.
