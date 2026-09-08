# Architecture

VibeShield is a private web service. Someone pastes a public GitHub repository
URL, watches the checks run, and gets a short list of things to fix, each with a
prompt they can paste into a coding agent. There is no CLI in the product flow,
no account, no stored history.

The service runs one scan at a time and keeps nothing: results live in memory for
an hour and do not survive a restart.

A model never decides anything. Scanner selection, publication, grouping,
ordering and wording are deterministic. There are no model calls in this service.

## Runtime Boundary

A repository submitted to VibeShield is untrusted input.

Each scan creates one fresh Microsandbox from the pinned toolchain image. The
repository is cloned inside that sandbox and every scanner runs there. The host
orchestrates the run, receives bounded and redacted exports, renders escaped
HTML, and destroys the sandbox when the run resolves. The host never executes
repository content, and the repository's own scanner configuration cannot
disable a selected check.

The application is never started. No install, build, test, migration or package
script runs at any point.

## Shape

```text
src/server.ts       process entry: bind, ownership reconciliation, shutdown
src/web/server.ts   HTTP routing, origin checks, admission
src/web/jobs.ts     the one job slot, terminal states, expiry, cleanup retries
src/web/pages.ts    the three server-rendered pages
src/web/assets.ts   one stylesheet and one browser script
src/scan/execute.ts stage sequencing, deadlines, sandbox lifecycle
src/scan/scanners/  one adapter per engine, raw export to normalized findings
src/scan/policy.ts  the reviewed rule set that may reach a reader
src/scan/report.ts  publication, grouping by root cause, prompts
```

## Scan Flow

```text
POST /scans
  -> prepare    fresh sandbox from the pinned image
  -> acquire    clone the default branch, at most 100 commits
  -> gitleaks   credentials in the snapshot and in fetched history
  -> opengrep   selected code rules, taint rules carry their flow
  -> osv        official OSV-Scanner over supported lockfiles
  -> trivy      container and infrastructure configuration
  -> zizmor     GitHub Actions workflows
  -> report     publication, grouping, prompts
  -> cleanup    destroy the sandbox, verified
```

Stages run in order inside one sandbox. Each engine has a two-minute budget and
the whole run has ten minutes. A failed, timed-out or malformed engine becomes a
coverage row, not a lost report: the remaining engines keep running and the
report is still built from what completed.

## Terminal States

A scan that starts always ends in one of three states, and each one is a page
worth reading:

| State | What the reader gets |
| --- | --- |
| `completed` | The report. |
| `cleanup-failed` | The report, plus closed admission until deletion is verified. |
| `failed` | A named reason and something to do about it. |

`failed` only happens when there is nothing to report: the repository could not
be read, it exceeded the acquisition limits, the sandbox never started, or the
run was stopped. `src/scan/execute.ts` maps its internal reason to a
`FailureCode`; `src/web/pages.ts` owns the sentence each code turns into. The
operator diagnostic keeps the precise internal reason, which is narrower than
what the page says.

A finished report is handed over even while cleanup is unresolved. Withholding it
does not remove a leaked sandbox; admission stays closed either way.

Cleanup retries are bounded so the process can go idle. A refused submission
starts one more attempt in the background, which is how a healed environment
reopens admission without an operator restart.

## Publication

Running more checks must not produce more noise.

`src/scan/policy.ts` lists the rules that may reach a reader, each with a
remediation key. A finding is published only when its rule is on that list, its
severity is high or critical, its evidence is present, and — for rules that
require it — the engine reported high confidence. Taint rules publish only with a
complete flow. Everything else is counted and reported as a number, never as a
card.

`src/scan/report.ts` then groups published findings by root cause: advisories for
one package version become one upgrade, and equivalent alerts collapse. The
resulting issues are ordered deterministically by severity and path.

## Report

`src/web/pages.ts` groups issues once more, by the fix they share, because a
reader acts on changes rather than on alerts. Nine flows fixed by the same
validation are one job with nine locations, not nine cards.

Jobs are ordered by a reviewed table of actions in `src/web/pages.ts`, not by
severity alone. Everything that survives publication is already high or critical,
so severity leaves the order to the path tiebreaker, which once put a workflow
note above a leaked credential. The table states the intent: a credential is out
of the owner's hands until it is revoked, injection and broken token checks let
someone in, and hardening defaults wait behind them. It is an ordering of work,
not a claim about exploitability.

Inside a job, application files come before files whose path looks like a test,
and the count of test files is stated. Test files are never dropped: a real key
leaks the same from a fixture.

The open page carries the first thing to do, then the jobs: what it is, how many
files it touches, why it matters, what to change in one plain sentence, and one
button that copies the fix. The first five jobs are open and the rest are folded,
but every job, location and piece of evidence stays on the page.

The reader is assumed not to open files. File paths, line numbers, code, the
prompt text, scanner names, versions, rule and advisory identifiers, coverage
states, the commit and the image digest all live inside disclosures. Coverage is stated
plainly and separately from findings: a report can hold real findings and
incomplete checks at the same time, and saying so is not an alarm.

Prompts are deterministic templates filled with observed evidence. They state
what was matched, what to change, how to verify it, and that nothing was
executed, so an agent does not overclaim.

## Progress

`GET /scans/:id/status` returns the public job state, one row per stage, the
public failure message when there is one, and whether a report exists. It never
returns report contents.

A stage reports what its check found — how many things to look at, or nothing —
rather than restating its own status. The progress page polls every two seconds
after the previous request settles, reconnects after a network error without
starting a second scan, and opens the report as soon as one exists.

## Limits and Ownership

Two CPUs and 4 GiB per sandbox, a 2 GiB workspace, 50,000 files and 500 MiB per
snapshot, 100 fetched commits, one hour of result retention and at most twenty
retained reports. See [runtime-limits.md](runtime-limits.md) for how the guest
enforces them.

Sandboxes and temporary directories are marked as service-owned. Startup
reconciles only owned resources; shutdown closes admission, aborts the active
job, waits for verified deletion and exits nonzero when it cannot confirm it.

## What This Does Not Establish

Passing checks and fixture tests prove orchestration and specific examples. They
are not evidence of detection precision or recall, of exploitability, or of
authorization and runtime coverage. See
[benchmark-methodology.md](benchmark-methodology.md).

## Legacy Code Still in the Tree

The deterministic web service is the product. The earlier CLI pipeline —
`src/cli.ts`, `src/application/`, `src/domain/`, `src/pipeline/`, `src/stages/`,
`src/reporting/`, the SQLite state store, the Joern backend and the OpenRouter
provider — is still present with its tests, and its `pnpm scan` / `pnpm resume`
scripts still run. None of it is reachable from the web service, and none of it
is a current product promise. Its research records stay as history:
[stage-1](stage-1-deterministic-security-core-plan.md),
[stage-2](stage-2-deep-static-security-graph-plan.md),
[phase-1 results](phase-1-capability-results.md),
[report v1](report-v1-research.md) and the
[terminated CWE-78 experiment](cwe78-flow-chain-experiment-termination.md).
Removing it is outstanding work.

## Retired Surfaces

The current architecture does not include Daytona, Pi mapping collectors,
repository-map-as-truth, attack-hypothesis evaluator loops, host-executed
scanners, local-path product input, model-written findings, or compatibility
shims for old run contracts.
