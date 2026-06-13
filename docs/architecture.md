# Architecture

VibeShield is a local CLI pipeline that accepts a GitHub repository URL and
returns an inspectable run directory. The current MVP produces repository
understanding artifacts, not a security verdict.

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
       -> baseline-summary.v1.json

  -> build Pi context pack
       -> compact repo/inventory facts
       -> baseline summary signal
       -> budget limits
       -> no raw scanner output/debug noise

  -> staged Pi repository mapping
       -> entry-points.v1
       -> sensitive-sinks.v1
       -> data-flows.v1
       -> project-understanding.v1

  -> write report.md
  -> write run.json/events.jsonl
  -> delete Daytona sandbox
```

## Deterministic Baseline

Baseline scanners run before Pi and provide normalized context for later
analysis. A scanner failure does not stop the whole baseline step. Each tool
records status, invocation metadata, diagnostics, and artifacts.

Current baseline tools:

- `syft`: SBOM generation.
- `trivy sbom`: vulnerability observations from SBOM input.
- `gitleaks`: secret observations.
- `actionlint`: conditional on GitHub Actions workflows.
- `zizmor`: conditional on GitHub Actions workflows.
- `checkov`: conditional on IaC/config candidates.

`osv-scanner` is deferred until its Daytona/network behavior is reliable enough
for MVP use.

## Pi Context Pack

`StepContextBuilder` creates `outputs/pi-context-pack.v1.json` from validated
artifacts. It keeps Pi input compact and excludes raw scanner output, logs,
debug metadata, and high-volume diagnostics.

The context pack includes:

- repository URL and commit SHA;
- inventory summaries and candidate paths;
- baseline summary signal;
- budget limits for Pi artifacts.

## Pi Repository Mapping

Phase 1 has four staged Pi mapping artifacts:

- `entry-points.v1`: HTTP routes, resolvers, RPC methods, CLI commands, event
  handlers, webhooks, cron jobs, upload handlers, and external format parsers.
- `sensitive-sinks.v1`: observable operation sinks such as DB queries, process
  execution, filesystem operations, parsing, redirects, outbound URL/client
  construction, crypto/randomness, and logging.
- `data-flows.v1`: source entrypoint to sink traces using prior entry point and
  sink artifacts.
- `project-understanding.v1`: synthesis only; it groups and summarizes previous
  artifacts and must not rediscover new facts.

## Pi Evaluator Loop

Each Pi stage uses the same minimal loop:

```text
collector Pi
  -> candidate JSON
  -> schema-only validation
  -> semantic evaluator Pi
       -> accepted: write final artifact and verdict
       -> rejected: pass feedback back to collector and retry
  -> max 3 attempts
```

The deterministic validator only checks JSON/schema/shape and budgets. It does
not try to prove whether a claim is semantically correct.

The collector is the exploration role. It runs with read/search/list tools and
must do the stage-specific discovery work before returning candidate JSON.

The semantic evaluator is evidence-led rather than blind. It also runs with
read/search/list tools, but starts from the candidate artifact, cited evidence,
prior stage input, and the stage contract:

- evidence supports the claim;
- kinds are not mislabeled;
- overclaims are rejected;
- data flows are not more confident than the evidence allows;
- project-understanding does not invent new entrypoints, sinks, or flows.

The evaluator may dig deeper when needed to validate or falsify a concrete
candidate claim, evidence reference, kind classification, trace, or explicit
coverage statement. It must not use broad repository rediscovery as the default
evaluation strategy or reject candidates for whole-repo completeness gaps unless
the omission is directly observable from the candidate, prior stage input, or
cited evidence.

If the evaluator rejects a candidate, its feedback is appended to the next
collector prompt. If all attempts are rejected, the stage fails with the final
semantic verdict preserved.

## Pi Runtime Observability

Live Pi jobs run through the Daytona runtime in Pi `--mode json`. VibeShield
does not print raw Pi output, thinking, tool arguments, or tool results to the
CLI. The sandbox runner filters Pi JSONL events into compact lifecycle messages
and streams only those sanitized events back to the host:

- runner start;
- `thinking...` when the agent starts a reasoning turn;
- one event per completed tool call, with tool name and a compact path/pattern
  when Pi exposes one;
- semantic evaluator rejection with the short reason before a collector retry;
- periodic heartbeat while Pi is still running;
- output start and completion/failure.

The final structured artifact is reconstructed from the final assistant text
and written to `outputs/pi/<stage>/<stage>.raw.redacted.txt`. The raw Pi JSONL
event stream is not stored as a user artifact.

Progress messages label whether the running Pi job is the stage `collector` or
the semantic `evaluator`, and include the attempt number when available.

## Artifacts

Successful runs write inspectable artifacts under the local run directory:

- `outputs/inventory.v1.json`
- `outputs/baseline/tool-availability.v1.json`
- `outputs/baseline/syft-sbom.json`
- `outputs/baseline-summary.v1.json`
- `outputs/pi-context-pack.v1.json`
- `outputs/entry-points.v1.json`
- `outputs/entry-points-semantic-evaluation.v1.json`
- `outputs/sensitive-sinks.v1.json`
- `outputs/sensitive-sinks-semantic-evaluation.v1.json`
- `outputs/data-flows.v1.json`
- `outputs/data-flows-semantic-evaluation.v1.json`
- `outputs/project-understanding.v1.json`
- `outputs/project-understanding-semantic-evaluation.v1.json`
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
