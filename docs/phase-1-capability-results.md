# Phase 1 end-to-end capability research results

Status: complete. Decision: **no detection winner**. No candidate-generation
approach is selected for integration.

Phase 0 remains the strict evidence-promotion gate, semantic grouping, and
Report v1 projection described in [Report v1 Phase 0](./report-v1-research.md).
Its synthetic cases remain contract regression fixtures and are not evidence of
detection precision, recall, competitiveness, or held-out generalization.

## Integrity and execution

The protocol was registered in
[`benchmarks/phase1/preregistration.json`](../benchmarks/phase1/preregistration.json)
before scanning. Scanner configuration and source hashes were frozen in
[`benchmarks/phase1/freeze.json`](../benchmarks/phase1/freeze.json) before the
held-out run. All four approaches received the same clean Git snapshot and no
expected-results file, source/sink list, route, control, graph edge, or flow.
Ground truth was read only by the scorer after all four raw outputs were
immutable.

The held-out scanner paths all completed on BenchmarkPython commit
`f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. A mechanical scorer correction is
recorded in
[`benchmarks/phase1/scorer-amendments.json`](../benchmarks/phase1/scorer-amendments.json):
it corrected coverage-field names and a Semgrep line-number field, rescored all
tools from the same raw outputs, and did not change TP, FP, FN, ratios, or the
decision.

The external corpora are suitable for capability measurement but not a proxy
for real-project performance. OWASP explicitly describes its runnable Java and
Python suites, expected-result files, and TP/FP/FN/TN scoring, and also notes
that its cases are generally simpler than real applications:
[OWASP Benchmark](https://owasp.org/www-project-benchmark/). The six real pairs
come from the manually vetted
[CWE-Bench-Java dataset](https://github.com/iris-sast/cwe-bench-java).

## Held-out results

BenchmarkPython 0.1 was the untouched held-out snapshot. A detection for CWE X
in a case that is not vulnerable to CWE X is an FP, including a wrong-CWE
detection. Results are one identity per tool, CWE, and official test ID; report
grouping is not involved.

| Tool | CWE | Cases (vuln/clean) | Eligible | TP | FP | FN | Precision | Recall | F0.5 |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| VibeShield | 22 | 168 (65/103) | yes | 0 | 0 | 65 | undefined | 0.0000 | undefined |
| CodeQL | 22 | 168 (65/103) | yes | 45 | 65 | 20 | 0.4091 | 0.6923 | 0.4456 |
| Semgrep CE | 22 | 168 (65/103) | yes | 2 | 2 | 63 | 0.5000 | 0.0308 | 0.1236 |
| direct Joern | 22 | 168 (65/103) | yes | 37 | 40 | 28 | 0.4805 | 0.5692 | 0.4960 |
| VibeShield | 78 | 20 (13/7) | **no** | 0 | 0 | 13 | undefined | 0.0000 | undefined |
| CodeQL | 78 | 20 (13/7) | **no** | 11 | 2 | 2 | 0.8462 | 0.8462 | 0.8462 |
| Semgrep CE | 78 | 20 (13/7) | **no** | 11 | 7 | 2 | 0.6111 | 0.8462 | 0.6471 |
| direct Joern | 78 | 20 (13/7) | **no** | 11 | 23 | 2 | 0.3235 | 0.8462 | 0.3691 |
| VibeShield | 79 | 89 (31/58) | yes | 0 | 0 | 31 | undefined | 0.0000 | undefined |
| CodeQL | 79 | 89 (31/58) | yes | 0 | 7 | 31 | 0.0000 | 0.0000 | 0.0000 |
| Semgrep CE | 79 | 89 (31/58) | yes | 0 | 62 | 31 | 0.0000 | 0.0000 | 0.0000 |
| direct Joern | 79 | 89 (31/58) | yes | 0 | 36 | 31 | 0.0000 | 0.0000 | 0.0000 |

CWE-78 is ineligible because it has only seven clean cases, below the
preregistered minimum of ten. Consequently only two cells are eligible, below
the required three, and no held-out aggregate threshold claim is valid. A tool
that emits no detections has undefined precision, not perfect precision.

VibeShield's full held-out scan produced 67 raw direct findings and 2,135 static
hypotheses, but none carried an explicit selected-CWE identity and none passed
the Phase 0 promotion gate. The scorer did not invent CWE mappings from titles
or wording. Its four coverage-loss reasons were three absent repository areas
(two GitHub Actions checks and IaC) plus skipped control-flow coverage. Semgrep
reported 122 syntax warnings. CodeQL and direct Joern reported no tool-execution
coverage errors.

### Java tuning context

These BenchmarkJava numbers were used only to exercise the tooling and scorer.
They are not held-out evidence and must not be cited as generalization. The
VibeShield tuning scan reached the 30-minute budget before it produced a report,
so it is coverage loss and has no score.

| Tool | CWE | TP | FP | FN | Precision | Recall | F0.5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL | 22 | 133 | 66 | 0 | 0.6683 | 1.0000 | 0.7158 |
| CodeQL | 78 | 126 | 64 | 0 | 0.6632 | 1.0000 | 0.7111 |
| CodeQL | 79 | 246 | 1,474 | 0 | 0.1430 | 1.0000 | 0.1726 |
| CodeQL | 89 | 272 | 207 | 0 | 0.5678 | 1.0000 | 0.6215 |
| Semgrep CE | 22 | 120 | 106 | 13 | 0.5310 | 0.9023 | 0.5786 |
| Semgrep CE | 78 | 117 | 109 | 9 | 0.5177 | 0.9286 | 0.5680 |
| Semgrep CE | 79 | 202 | 254 | 44 | 0.4430 | 0.8211 | 0.4879 |
| Semgrep CE | 89 | 253 | 170 | 19 | 0.5981 | 0.9301 | 0.6441 |
| direct Joern | 22 | 68 | 52 | 65 | 0.5667 | 0.5113 | 0.5547 |
| direct Joern | 78 | 113 | 79 | 13 | 0.5885 | 0.8968 | 0.6320 |
| direct Joern | 79 | 0 | 458 | 246 | 0.0000 | 0.0000 | 0.0000 |
| direct Joern | 89 | 174 | 106 | 98 | 0.6214 | 0.6397 | 0.6250 |

CodeQL reported two repeated extraction notifications in each Java cell;
Semgrep and direct Joern reported none. The complete per-cell records, including
denominators and coverage loss, are preserved in the machine-readable result
summary.

## Real vulnerable/fixed pairs

Each cell below is the raw target-CWE alert count on vulnerable/fixed commits.
An alert was accepted as verified only if its root-cause path matched the
preselected fix and disappeared or was blocked for the semantic reason in that
fix. Merely changing line numbers or retaining an alert on the fixed revision
does not verify the CVE.

| Pair | CWE | CodeQL v/f | Semgrep v/f | Joern v/f | VibeShield v/f | Verified |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| MyFaces CVE-2011-4367 | 22 | 24/23 | 1/1 | 0/0 | 0/0 | 0 |
| Undertow CVE-2014-7816 | 22 | 3/3 | 0/0 | 2/7 | 0/0 | 0 |
| XStream CVE-2013-7285 | 78 | 0/0 | 0/0 | 0/0 | 0/0 | 0 |
| ActiveMQ CVE-2014-3576 | 78 | 1/1 | 0/0 | 3/3 | 0/0 | 0 |
| Keycloak CVE-2014-3656 | 79 | 1/1 | 0/0 | 0/0 | 0/0 | 0 |
| AntiSamy CVE-2016-10006 | 79 | 0/0 | 0/0 | 0/0 | 0/0 | 0 |

The surviving baseline alerts were outside the registered fix methods or
survived the fixed revision. They are not counted as confirmed findings. Thus:

- independently verified real-repository findings: **none**;
- confirmed VibeShield findings missed by CodeQL/Semgrep/Joern: **none**;
- confirmed baseline findings missed by VibeShield: **none**;
- unique detection advantage: **not demonstrated**.

SecBench.js was also scanned end to end by all four approaches. It is
vulnerable-only and cannot establish precision. CodeQL normalized 200 CWE-78
and one CWE-79 alert, Semgrep normalized four CWE-22 alerts, and the direct
Joern pack and VibeShield normalized no explicit selected-CWE alert. VibeShield
did produce 1,098 raw direct findings and 990 static hypotheses, with zero
publishable static hypotheses. These counts are breadth/coverage observations,
not accuracy results.

## Capability audit

States apply to the exact frozen runners and query packs used here, not to every
possible custom query a tool could support. Documentation without a successful
relevant probe is at most `partial`.

| Capability | VibeShield | CodeQL security-extended | Semgrep CE rules | direct Joern query |
| --- | --- | --- | --- | --- |
| Interprocedural value flow | not demonstrated | demonstrated | not demonstrated | demonstrated on Java; not on JS |
| Call resolution | partial | demonstrated | partial | demonstrated on Java |
| Aliases and object fields | not demonstrated | partial | partial | partial |
| Control dependence and dominance | not demonstrated | partial | not demonstrated | partial |
| Value-matched sanitizers/barriers | not demonstrated | partial | partial | not demonstrated |
| Framework route discovery | demonstrated | partial | partial | not demonstrated |
| Auth guards, identities, and roles | not demonstrated | partial | not demonstrated | not demonstrated |
| Privileged-operation semantics | partial | partial | partial | partial |
| Data-store flows | partial | demonstrated | demonstrated on tuning rules | demonstrated on Java |
| External-service flows | partial | partial | not demonstrated | not demonstrated |
| CI/IaC | demonstrated | not demonstrated by this runner | not demonstrated by this runner | not demonstrated |
| Dependency reachability | demonstrated structurally | not demonstrated by this runner | not demonstrated | not demonstrated |

Key executable evidence:

- VibeShield's current `flows` extraction emits framework method-parameter
  seeds. Its later graph traversal connects `receives`, `registers`, `calls`,
  lexical `flows_to` edges, and always writes empty `controlNodeIds`; it is not a
  value-flow proof. All production runs reported `control_flow: skipped`.
- VibeShield did discover 2,469 boundary candidates on held-out Python and
  checked one CI/IaC resource plus 777 of 1,069 dependency-usage records on
  SecBench.js. This demonstrates route discovery and structural dependency/CI
  context, not vulnerability detection accuracy.
- CodeQL emitted path SARIF for 3,166 Java tuning results, including 488 paths
  whose locations crossed files. Its database represents AST, data-flow, and
  control-flow graphs, its libraries expose call-graph and global-flow APIs, and
  standard framework support includes Django, Flask, FastAPI, Spring, and
  Spring Security: [CodeQL overview](https://codeql.github.com/docs/codeql-overview/about-codeql/),
  [Java data flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-java/),
  [call graph](https://codeql.github.com/docs/codeql-language-guides/navigating-the-call-graph/),
  [framework support](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/).
  The frozen security suite did not include a dedicated dominance, value-state,
  identity/role, CI/IaC, or dependency-reachability probe, so those remain
  partial or not demonstrated here.
- Semgrep CE is explicitly per-file. Its rules can define sources, sinks,
  propagators, and sanitizers, while interfile analysis is proprietary:
  [Semgrep glossary](https://semgrep.dev/docs/writing-rules/glossary). The run
  used CE 1.151.0, not Pro Engine.
- The direct Joern query materialized 2,743 Java paths, 2,182 with source and
  sink endpoints in different files, using `reachableByFlows`. The CPGQL API
  also exposes `controls`, `controlledBy`, `dominates`, and post-dominance, but
  the frozen query did not invoke them:
  [Joern data-flow steps](https://docs.joern.io/cpgql/data-flow-steps/),
  [Joern control-flow steps](https://docs.joern.io/cpgql/control-flow-steps/),
  [Joern calls](https://docs.joern.io/cpgql/calls/).

## Decision and next research layer

The minimum gate fails on recall, eligible-cell count, comparative F0.5,
verified real findings, and unique advantage. Approach B is therefore **not**
finalized and no alternative detector is declared the winner. Current
VibeShield value is orchestration, triage, evidence provenance, and reporting.

The next bounded research layer should replace structural source-to-sink graph
reachability with an explicit value-flow backend contract:

1. materialize source, sink, and full value-flow paths from Joern
   `reachableByFlows` or an equivalent CodeQL backend rather than method-input
   seeds plus BFS;
2. attach call-resolution confidence, field/alias steps, and coverage loss to
   every path;
3. extract control dependence/dominance and require a sanitizer/control to
   match the same value and sink semantics;
4. add explicit framework models for routes, auth guards, identities/roles,
   data stores, privileged operations, and outbound services;
5. develop only on a new tuning split, then use a new untouched held-out corpus
   because BenchmarkPython has now been consumed;
6. retain the Phase 0 evidence gate as a publication boundary, but do not use
   grouping or report cleanup to measure detection accuracy.

Report cleanup stops here because no detection approach was selected.
