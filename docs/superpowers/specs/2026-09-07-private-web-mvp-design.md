# Private web MVP

Date: 2026-09-07
Status: agreed product scope; written design awaiting review

## Product decision

VibeShield hides the complexity of established security tools behind one web
flow: submit a public GitHub repository, watch progress, receive a short report
with concrete instructions for a coding agent. Users do not choose scanners,
configure rules, use a CLI, or interpret raw alerts.

The first deployment is private, without application authentication. It is
intended for localhost or an operator-controlled private network. Public
multi-user hosting, accounts, billing, saved history, and continuous monitoring
are outside this design.

The product promise is: find important, common security problems that the
completed checks can establish, and explain how to fix them. It does not promise
an exhaustive audit, verified exploitability, or that an application is safe.

This design defines the target behavior. Until implementation lands,
[architecture.md](../../architecture.md), the README, and AGENTS.md still describe
the existing CLI. Update those entry points with the implementation; historical
research records remain evidence, not current product promises.

## Evidence and reuse

The current repository has a scanner pipeline, isolated execution, normalization,
remediation templates, and report rendering. The inspected checkout passed lint,
typecheck, 287 tests, and the live Microsandbox tool-availability smoke. That smoke
does not prove an end-to-end repository scan or detection quality.

Two current limitations need direct replacement:

- OpenGrep runs only two custom patterns, for `eval` and `new Function`.
- The custom OSV script reads exact npm versions from package manifests; it is
  not the official OSV-Scanner and does not resolve lockfiles.

The [Phase 1 results](../../phase-1-capability-results.md) did not establish added
vulnerability-detection value from the existing Deep Static implementation.
The [terminated CWE-78 experiment](../../cwe78-flow-chain-experiment-termination.md)
must not be resumed as part of this MVP.

Reuse working scanner adapters, redaction, normalization, grouping, remediation
templates, and relevant tests. Simplify their contracts where the web-only flow
requires it. Do not preserve obsolete modes or old-run compatibility.

## User flow

### Submit

The home page has one public GitHub repository URL field and a Scan button.
Accept HTTPS repository-root URLs on github.com, normalize an optional `.git`
suffix, and reject credentials, alternate hosts, local paths, and branch/file
URLs. Scan the default branch and show the resolved commit in the result.

Invalid input receives an inline explanation. A missing, private, or inaccessible
repository receives a clear acquisition error. No GitHub credentials are used.

Only one scan runs at a time. While busy, the page explains that another scan is
running; requests are not silently queued. Repeated submission cannot create
parallel jobs.

### Progress

Starting a scan redirects to an opaque job URL. Show actual stage states:
preparing the environment, fetching the repository, running applicable checks,
and preparing the report. Stages may be waiting, running, completed, skipped, or
failed. Do not invent percentage progress.

The page polls a small status endpoint every two seconds. Reloading or temporarily
closing the page does not interrupt the scan. When it completes, the page opens
the report automatically. A network error offers retrying status retrieval, not
starting another scan.

### Report

Show the repository and commit, important grouped issues, and check completeness.
Each issue contains a plain-language title, why it matters, file/line or dependency
evidence, remediation guidance, and a copyable prompt for a coding agent.

Expand the first five issue groups initially; make any remaining important groups
available on the same page with their count. Never discard an important issue to
meet a presentation limit. Do not expose raw scanner dumps, graph views, or
speculative attack cards as the primary experience.

Keep issue status and coverage separate. A report can contain important findings
and incomplete checks at the same time. With no publishable findings, say either
"No important problems found by the completed checks" or "Scan incomplete" as
appropriate. Do not present a deployment approval or security score.

Prompts are deterministic templates populated with evidence, the intended fix,
and a concrete verification step. They must distinguish observed facts from
exploitability assumptions. Secret values are redacted before leaving the sandbox
and never copied into prompts. Repository text is untrusted quoted evidence,
not instructions for the scanner or the remediation template.

## Scanner composition

| Component | MVP responsibility |
| --- | --- |
| Gitleaks | Secrets in the current snapshot and a bounded default-branch history. |
| OpenGrep | Code security checks using selected, versioned existing rules, including appropriate taint rules. |
| Official OSV-Scanner | Known vulnerable dependencies from supported manifests and lockfiles. |
| Trivy config | Serious misconfigurations in supported infrastructure and container configuration files. |
| zizmor | Security-relevant GitHub Actions findings. |

These are the five required engines. Syft, actionlint, and the separate Trivy
dependency scan are not required MVP stages. Remove them from the default
toolchain unless implementation identifies a concrete dependency of one of the
five required checks; any such dependency must be documented and tested.

Use existing published rules with licenses suitable for inclusion in VibeShield.
Record their upstream source, revision, license, and enabled rule IDs. Pin tool
versions and rule revisions in the built image; scans do not download arbitrary
latest rules. Vulnerability database freshness is separate and is reported when
refresh fails. Repository-supplied scanner policies must not silently disable
the service's selected checks.

The first code-analysis acceptance target is JavaScript/TypeScript web projects.
Other languages and dependency/configuration formats may be scanned when the
selected engines and rules support them, but coverage must list actual support
and skips. Do not claim a language is covered because its files were discovered.
Do not install application dependencies or execute application scripts to improve
coverage. A missing or unsupported lockfile is a coverage limitation, not proof
that dependencies have no vulnerabilities.

For history scanning, fetch at most the latest 100 default-branch commits without
submodules or Git LFS downloads. Report the actual inspected history and whether
it is truncated. Secrets found only in history identify their commit and historical
path; remediation prioritizes revocation/rotation rather than merely deleting a
line in the current snapshot.

## Publication policy

Running more checks must not automatically produce more user-facing noise.

- Enable reviewed security rules that have a concrete remediation and acceptable
  behavior on vulnerable and clean examples. Do not turn on every upstream rule.
- Publish high/critical findings from these rules when required evidence is
  present. A medium-severity rule needs an explicit reviewed policy entry to be
  promoted; generic medium/low hardening advice remains outside the issue list.
- Require rule-specific evidence. A dangerous function name alone does not prove
  remote code execution, and a package advisory does not prove runtime reachability.
- Treat test fixtures, documentation examples, generated files, and application
  code explicitly. Do not suppress secrets solely because they are in tests.
- Group equivalent alerts by root cause. Dependency advisories with equivalent
  identifiers are deduplicated; compatible upgrades can share one action while
  retaining affected-package and advisory evidence.
- Preserve dependency scope where the scanner provides it. Do not automatically
  dismiss development dependencies: build and CI exposure may still matter.
- Unsupported output, missing evidence, and parser failures must not become a
  successful empty scan. Report their effect on completeness.

The report generator consumes one normalized finding and coverage contract.
Scanner-specific severity mappings and publication decisions remain inspectable
and testable. An LLM does not select, validate, rank, or rewrite findings.

## Runtime and temporary state

Keep TypeScript/Node and the working Microsandbox adapter. Use one server process,
simple server-rendered pages, a small browser script for polling and copying, and
one in-process job coordinator. No separate frontend application, broker, or
persistent database is needed.

The server binds to loopback by default. Starting it and preparing the toolchain
are operator commands; the scan/resume CLI and local-path product input are
removed. Container setup details do not appear in the normal user flow.

Each scan gets a fresh sandbox. Clone and run scanners there. The host receives
only bounded, expected, redacted artifacts and renders escaped content. Never run
the repository's app, hooks, builds, tests, migrations, or package scripts. Failure
to start the sandbox fails the job rather than executing scanners on the host.

Initial limits are two CPUs, 4 GiB sandbox memory, a ten-minute total deadline,
and two minutes per scanner. Bound acquisition to two minutes, the snapshot to
50,000 files and 500 MiB, and total job workspace disk to 2 GiB. Enforce the
workspace bound during acquisition, not only after cloning. Timeout handling must
stop the underlying command or destroy the sandbox, not just reject a promise.
Do not truncate scanner results silently to fit artifact limits.

A failed scanner does not discard successful findings from other checks. Fatal
acquisition/runtime errors produce an actionable failure page. On completion,
failure, or timeout, destroy the sandbox and remove temporary raw artifacts.
Cleanup failure is visible to the operator and prevents another scan from
accumulating resources until cleanup succeeds.

Keep normalized results in memory for one hour after completion, then expire them.
Retain at most 20 completed reports, evicting the oldest if needed. There is no
history screen or permanent result storage. Unknown, expired, and pre-restart job
URLs show an unavailable-result page with a link to start a new scan. Responses
use `Cache-Control: no-store`.

Handle server shutdown by terminating active work and cleaning temporary resources.
On startup, reconcile only VibeShield-owned temporary directories and orphaned
sandboxes. Do not restore interrupted jobs or inspect/delete unrelated resources.

## Deep analysis boundary

Remove the existing mandatory coupling to Joern, SecurityGraph, static hypotheses,
model enrichment, and graph reporting from the shipped MVP. Remove OpenRouter and
its configuration. Preserve historical research documents with explicit status;
do not retain an undocumented experimental product mode or obsolete contracts.

A future deeper engine must use an established scanner/query pack, demonstrate
additional useful findings on previously unseen vulnerable/fixed repositories,
avoid regressions on clean controls, and fit measured time/resource budgets.
CodeQL, a commercial engine, or stock joern-scan requires its own capability and
distribution-terms evaluation. None is a dependency of this MVP.

## Acceptance

Implementation is complete only after all of the following are demonstrated:

1. Lint, typecheck, tests, and production build pass. Production starts as a web
   server; the user can complete the flow without a scan CLI.
2. Browser verification covers submission, progress updates, page reload,
   completion, report rendering, prompt copying, and starting another scan.
3. A real public GitHub repository passes through acquisition and actual engines
   in Microsandbox to the browser report. Record the repository, commit, image
   and rule revisions, duration, coverage, and findings; a fake runtime is not
   sufficient evidence.
4. Controlled integration fixtures exercise each of the five actual engines,
   including a historical secret and lockfile dependency. Vulnerable/fixed and
   clean controls exercise publication and suppression. Fixture tests prove
   those cases, not general detection accuracy.
5. Busy submissions, inaccessible repositories, unsupported inputs, one scanner
   failing, overall timeout, report expiry, and server restart have explicit
   behavior. Failed checks cannot turn into a clean result.
6. Malicious repository strings render as text, secret evidence is redacted,
   scanner execution stays isolated, and job resources are removed after failure
   as well as success.
7. README, architecture, AGENTS.md, environment examples, scripts, and the
   toolchain describe the web-only deterministic product. Removed modes have no
   dangling imports, commands, or misleading current documentation. Generated
   outputs remain outside Git.

Do not claim broad detection precision, recall, exploitability, authorization
coverage, or runtime validation from passing infrastructure and fixture tests.
