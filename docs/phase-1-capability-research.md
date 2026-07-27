# Phase 1 end-to-end capability research preregistration

Status: preregistered before the first Phase 1 scanner run on 2026-07-17.
Execution is complete; see the [Phase 1 results](phase-1-capability-results.md).

This phase decides whether VibeShield has a detection advantage. Phase 0 report
grouping and publication behavior is frozen and is not an accuracy signal. No
detection approach is selected before this protocol finishes.

## Isolation contract

Every scanner invocation receives only:

1. a raw, pinned Git worktree snapshot;
2. the scanner or query configuration fixed for that approach;
3. an output directory and resource limits.

Scanner processes must not receive benchmark expected-results files, labels,
patch metadata, vulnerable line lists, source/sink annotations, route lists,
controls, graph edges, or precomputed flows. Each approach performs its own
parsing or extraction, graph construction where applicable, candidate
generation, and validation. Ground truth is mounted or read only by a separate
scorer after every raw tool result is immutable.

The run manifest records target URL, target commit, dirty-state rejection,
scanner version, configuration hash, database or ruleset revision, command,
start/end time, exit state, and raw-result hash. A run with missing provenance
is reported as coverage loss, not silently discarded.

The preregistered command runtime budget is 30 minutes. A timeout is a failed
full scan and coverage loss, never a partial accuracy result. CodeQL is capped
at 8 GiB analysis RAM, direct Joern at 10 GiB and 8 CPUs, Semgrep at 30 seconds
per file and 5 MiB per target, and VibeShield uses the production Microsandbox
allocation (4 GiB and 2 vCPUs). These limits remain fixed for tuning, held-out,
and real-pair runs.

## Candidate-generation approaches

The comparison contains four materially different generators:

1. **VibeShield production scan.** The complete CLI path runs its own repository
   snapshot, toolchain extraction, direct scanners, graph construction,
   correlation, and evidence validation. Scoring uses raw direct findings and
   pre-projection hypotheses; Report v1 grouping and caps are ignored.
2. **CodeQL standard security queries.** CodeQL builds a language database from
   the snapshot and executes the pinned standard `security-extended` suite.
   Candidates come from QL library call resolution and interprocedural
   data-flow/path queries.
3. **Semgrep OSS rules.** A pinned `semgrep-rules` revision runs directly over
   the snapshot. Candidates come from AST patterns and taint-mode rules. No
   VibeShield or Joern candidate list is supplied.
4. **Direct Joern CPGQL.** Joern imports the raw snapshot and executes a pinned
   standalone query pack. The queries identify their own sources, sinks,
   calls, data-flow paths, and controls from the CPG. They do not consume the
   VibeShield `SecurityGraph` or its candidates.

CodeQL, Semgrep, and direct Joern are baselines, not post-filters over a shared
candidate set. Default/pinned baseline queries are not edited after their first
run. Direct Joern and VibeShield changes may be developed only on the tuning
snapshot and must be frozen before any held-out scan.

## Corpora and split

All repositories are pinned by commit in the run registry before execution.

| Role | Snapshot | Use |
| --- | --- | --- |
| Tuning | OWASP BenchmarkJava 1.2, `79b9bd6177e07991a9c11dc19e457c840e229931` | Develop and reject candidate generators; scorer may use official expected results |
| Held-out | OWASP BenchmarkPython 0.1, `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | One full-snapshot scan per frozen approach; no rule development or result inspection before freeze |
| Real pairs | CWE-Bench-Java registry, `afe0ebd0adc237abb46255f9cd479b1d71819136` | Confirm findings on real code and test whether the finding disappears for the right semantic reason |
| Real-repository breadth | SecBench.js, `bc315621913899dcaa7613cd60948514ae63bdfe` | JS/TS capability and real-finding lane; vulnerable-only cells cannot establish precision |
| External cross-check | NIST SARD/Juliet Java cases where snapshot/tool limits permit | Confirm that OWASP-specific structure is not the only detected form |

Real-pair selection is independent of scanner output: take the first two
reproducible entries in lexical CVE order for each of CWE-22, CWE-78, and CWE-79
from the pinned CWE-Bench-Java registry. If an entry cannot be reproduced, keep
the failure in the registry as coverage loss and advance to the next entry; do
not select based on whether a tool detects it. JS/TS and Go results are reported
by language and CWE but remain exploratory until both vulnerable and clean
denominators meet the rule below.

The resulting pre-scan pair registry is:

| CWE | CVE | Repository | Vulnerable revision | Fixed revision |
| --- | --- | --- | --- | --- |
| 22 | CVE-2011-4367 | `apache/myfaces` | `bedac49daffc3cb792fa19884620af01ab5a01ab` | `b9b2e00bb53d3eb435256c5a140b83f7d6251b55` |
| 22 | CVE-2014-7816 | `undertow-io/undertow` | `4aa98c80fa9962235c94f8666c30793d0018f95d` | `28f244e63f558ba99a197813cfd5eee461b52b4c` |
| 78 | CVE-2013-7285 | `x-stream/xstream` | `768c6e417a75e7732fc591bee844e5e81af56a7d` | `6344867dce6767af7d0fe34fb393271a6456672d` |
| 78 | CVE-2014-3576 | `apache/activemq` | `8938d14d434447193b02ba635606aa0fb7a80353` | `f07e6a53216f9388185ac2b39f366f3bfd6a8a55` |
| 79 | CVE-2014-3656 | `keycloak/keycloak` | `3b071b83aa0444749eba851fdbe0f2ed47932410` | `63b41e2548cbc20bd3758e34a82d880e177bf24c` |
| 79 | CVE-2016-10006 | `nahsra/antisamy` | `8bebe1eb2ec1ac23e34111e9d06024d7dab7fa25` | `5a783b4116a21a12ab10f57cd1c88616902af633` |

For multi-commit fixes the fixed revision is the last commit listed by the
pinned registry, so the complete human patch sequence is present.

## Preregistered scored cells

The held-out capability gate uses these Python cells from the complete OWASP
BenchmarkPython scan:

- Python / CWE-22 path traversal;
- Python / CWE-78 command injection;
- Python / CWE-79 cross-site scripting.

Java / CWE-22, CWE-78, CWE-79, and CWE-89 on BenchmarkJava are tuning cells and
cannot be cited as held-out generalization. Other observed languages and CWEs
are emitted as separate cells, never pooled to hide a weak family.

A language/CWE cell is eligible for a threshold claim only when it contains at
least 20 scored cases, including at least 10 vulnerable and 10 clean/guarded
cases, after declared coverage loss. The published held-out aggregate also
requires at least 100 total scored cases across at least three eligible cells.
Ineligible cells retain TP, FP, FN, and coverage counts but their ratios are
labelled `insufficient_denominator` and cannot satisfy a gate.

## Result normalization and metrics

Raw results are normalized only after scanning. A finding matches an OWASP case
by the official test-case identifier derived from its result location and the
official CWE. For an explicit interprocedural path whose sink is in a shared
helper, the scorer may use the source endpoint's test identifier while retaining
the helper sink as the finding location. A detection for CWE X in any official
case that is not vulnerable to CWE X is an FP, including a wrong-CWE detection.
Matching does not use report grouping, wording similarity, or a hard-coded
semantic identity. Duplicate results for one tool, case, and CWE are one
candidate for scoring but remain visible in raw output.

For every tool, language, and CWE, the scorer emits:

- TP, FP, and FN;
- precision `TP / (TP + FP)`;
- recall `TP / (TP + FN)`;
- F0.5 `1.25 * precision * recall / (0.25 * precision + recall)`;
- false blockers: clean/guarded cases that make VibeShield return a deploy
  blocker (baseline tools report `not_applicable`);
- coverage loss: expected cases not eligible for matching, grouped by reason;
- independently verified real-repository findings;
- unique verified findings: true findings not matched by any other approach on
  the same snapshot, CWE, root-cause location, and vulnerable/fixed behavior.

No scorer field may assert recall preservation, model-on/off identity,
repository independence, or semantic equivalence without two measured runs or
explicit adjudication. Zero denominators produce no ratio, never `1.0`.

## Capability audit

Each approach is tested with documentation evidence and an executable probe for:

- interprocedural data flow and call resolution;
- aliases, object fields, and value propagation;
- control dependence and dominance;
- value-matched sanitizers or barriers;
- framework route discovery and route-to-handler flow;
- authentication guards, identities, and roles;
- privileged operations;
- data stores and external services;
- CI/IaC analysis;
- dependency reachability.

The only allowed states are `demonstrated`, `partial`, `not demonstrated`, and
`not applicable`, each with a raw artifact or primary-source citation. A tool's
documentation claim without a successful relevant probe is at most `partial`.

## Freeze and held-out rule

Before the held-out worktree is scanned, the registry must contain hashes for:

- the VibeShield source/diff under test;
- CodeQL CLI and query-pack locks;
- Semgrep binary and rules revision;
- Joern binary/image and direct-query pack;
- every runner and normalizer.

Initial tool pins are CodeQL bundle 2.26.1, Semgrep CE 1.151.0 with
`semgrep-rules` commit `e5b5a42ec061854378c11e0d01f19250b52bc2e9`,
and Joern 4.0.565. Exact archive, image, runner, and query hashes are added to
the freeze registry after installation and before held-out execution.

After that freeze, held-out scanner output is generated once. Any scanner or
normalizer correction invalidates all held-out outputs and requires a new
versioned evaluation; it cannot reuse previous held-out results for tuning.
Scorer-only corrections are allowed when they are mechanical and recorded, and
must rescore every tool identically.

## Capability gate and decision rule

VibeShield may claim a detection win only if all of the following hold on the
untouched held-out full scan:

- precision is at least 0.90 in every eligible preregistered cell and in the
  eligible micro aggregate;
- recall is at least 0.80 in every eligible preregistered cell and aggregate;
- there are zero deploy blockers on clean/guarded cases;
- F0.5 is no worse than the best CodeQL, Semgrep, or direct-Joern result in each
  eligible cell and aggregate;
- every result comes from raw-source full scans with declared coverage loss;
- at least three findings in at least two real repositories are independently
  verified against vulnerable and fixed revisions;
- all VibeShield-only verified findings and all baseline-only verified findings
  are listed explicitly.

At least one independently verified VibeShield-only real-repository finding is
required to claim a unique detection advantage. If the gate fails or there is
no unique advantage, the decision is **no detection winner**. The reported
current value of VibeShield is then orchestration, triage, evidence provenance,
and reporting, followed by a proposal for the next bounded research layer.

Report cleanup, card caps, semantic grouping, and ranking occur only after this
detection decision and never contribute to TP, FP, FN, precision, recall, or
F0.5.
