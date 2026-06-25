# Architecture

VibeShield is a local Quick Scan pipeline for AI-generated and beginner-built web
projects. It accepts either a public GitHub repository URL or a local Git
worktree root and returns an inspectable run directory with:

- `manifest.json`;
- `report.json`;
- `report.md`;
- `report.html`.

The current product goal is not a full security review. It is a small,
prioritized **Agent Fix Pack**: concrete findings with file/line evidence,
plain-language explanation, and a prompt the owner can paste into a coding
agent.

## Runtime Boundary

Repositories scanned by VibeShield are untrusted input.

The default runtime creates one fresh Microsandbox per scan. GitHub input is
cloned inside the sandbox. Local input must be a Git worktree root; the host
creates a Git-filtered archive, uploads it, and extracts it inside the sandbox.

The host orchestrates the run, stores artifacts, renders reports, and performs
the optional OpenRouter remediation call. Scanner tools run inside the sandbox,
never on the host. The scanned app, package scripts, build commands, and git
hooks are not executed by VibeShield.

Network is enabled for iteration 1. Vulnerability databases are refreshed at run
start, and freshness is recorded in the manifest. If the sandbox/toolchain is
unavailable, the scan fails clearly instead of falling back to host execution.

## Flow

```text
vibeshield scan <github-url-or-local-git-root>
  -> source.resolve
       GitHub: clone inside Microsandbox
       local: upload Git-filtered snapshot into Microsandbox
  -> toolchain.refresh
       refresh scanner vulnerability databases
  -> snapshot.manifest
       origin, commit when available, file hashes, exclusions, tool/DB versions
  -> inventory.detect
       languages, package manifests, GitHub Actions workflows, IaC/config files
  -> scan.*
       gitleaks
       opengrep
       syft
       trivy vuln
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
       optional bounded OpenRouter calls for wording/prompt enhancement
  -> report.compose
       one SecurityAssessment
  -> report render
       terminal receipt + report.json + report.md + report.html
  -> destroy sandbox
```

## Scanner Set

The implemented check stages are:

| Check | Tool | Runs When | Purpose |
| --- | --- | --- | --- |
| `secrets.gitleaks` | `gitleaks` | Always | Detect committed secret-like values. |
| `code-patterns.opengrep` | `opengrep` | Source files exist | Detect simple unsafe code patterns. |
| `sbom.syft` | `syft` | Dependency manifests exist | Produce a CycloneDX SBOM artifact. |
| `dependencies.trivy` | `trivy fs --scanners vuln` | Dependency manifests exist | Detect vulnerable dependencies. |
| `github-actions.actionlint` | `actionlint` | Workflow files exist | Parse and lint GitHub Actions workflows. |
| `github-actions.zizmor` | `zizmor` | Workflow files exist | Detect GitHub Actions hardening issues. |
| `iac.trivy-config` | `trivy config` | IaC/config files exist | Detect infrastructure/config issues. |

That is seven check stages backed by six scanner binaries because `trivy` is
used for both dependency and IaC checks.

Each check records truthful coverage:

- `checked`: the applicable tool ran and produced parseable output;
- `skipped`: the check was not applicable to this repository;
- `failed`: the tool or parser failed;
- `degraded`: supporting data such as vulnerability DB freshness is stale or
  incomplete.

Required coverage loss blocks a green verdict. Other completed checks still
produce a useful Fix Pack.

## Evidence And Artifacts

Raw scanner outputs are redacted before entering the blob store. Normalized
findings carry only redacted snippets, tool/rule metadata, severity, confidence,
locations, evidence IDs, and stable fingerprints.

The scanned source tree itself is not stored as a run artifact. The manifest is
the reproducibility boundary: origin, commit SHA when available, file list,
hashes, exclusions, source hash, tool versions, and DB freshness.

## Deterministic Triage

The model does not decide whether something is a finding, how severe it is, how
important it is, or what verdict the repository gets.

Those are computed before any model call:

- scanner output is normalized into `Evidence` and `Finding`;
- findings are grouped into deterministic `ActionCandidate`s;
- priority and verdict impact are rule-computed;
- the final verdict is rule-computed from findings and coverage.

## Remediation

`remediation.generate` first creates catalog remediation for every ranked
action. The optional model call is enhancement-only:

- OpenRouter key comes from `OPENROUTER_API_KEY`;
- model name comes from `VIBESHIELD_REMEDIATION_MODEL` or the default in code;
- only the top bounded action set is sent;
- each action is enhanced in a separate bounded request with limited
  concurrency;
- per-action context is capped to representative findings/files plus summary
  counts;
- model output is validated against expected candidate IDs and unsafe path
  rules;
- invalid or unavailable model output falls back to the deterministic catalog.

This keeps the deterministic result complete without any model.

## Reports

The terminal is intentionally short: progress on stderr, then a receipt with
repository, verdict, report path, and the static-scan limitation. Full Fix Pack
details live in `report.html` and `report.md`.

`report.json` is the machine-readable `SecurityAssessment` and keeps the
inspectable contracts: manifest summary, repository identity, coverage,
findings, evidence, clusters, ranked actions, verdict, and limitations.

## State And Resume Direction

Runs are recorded through SQLite state and content-addressed blob storage.
Stages are defined through the stage registry and executed in dependency order.

Minimal resume is the next product step: re-run missing, failed, or stale stages
from durable state without starting over. Old MVP surfaces such as Daytona, Pi
mapping collectors, repository-map-as-truth, attack-hypotheses, evaluator loops,
and in-memory run registries are not part of the current architecture.
