# Phase 0: evidence promotion and Report v1 projection

This record describes a contract-level implementation spike completed in July
2026. It is **Phase 0 only**. It does not select a detection approach and does
not establish detection precision, recall, competitiveness, or held-out
generalization.

The Phase 0 scope is deliberately narrow:

- a strict evidence promotion gate for already-generated hypotheses;
- semantic grouping of already-generated traces by root cause;
- suppression of validation cards already owned by direct findings;
- the `Fix now`, `Validate next`, and technical-appendix Report v1 projection.

Detection selection is deferred to the end-to-end research preregistered in
[phase-1-capability-research.md](phase-1-capability-research.md). Report cleanup
must not be used as evidence that detection became more accurate.

## Fresh pre-change observation

The pre-change scanner ran in a clean detached worktree at commit
`90f09895a920b00f19925db43162bf23202b72de`. Node 26.0.0 and pnpm 10.33.3 were
used. Lint, typecheck, and build passed; two old Gate 3 acceptance tests failed.

A fresh no-model scan produced 3 direct findings and 20 static hypotheses. All
20 hypotheses were inconclusive because data-flow coverage was partial, yet the
old report exposed two owner-facing attack cards. Nineteen correlations came
from generic content/resource paths in benchmark and documentation material;
one dependency trace overlapped a direct action. This observation motivated a
safer publication boundary. It was not a scored detection baseline.

Tool provenance for that run was gitleaks 8.30.1, opengrep 1.25.0, syft 1.48.0,
trivy 0.72.0, actionlint 1.7.12, zizmor 1.27.0, and Joern 4.0.565. The Trivy DB
timestamp was `2026-07-17T07:25:53.058Z`; the exact OSV data revision was not
available in the manifest.

## Mechanisms implemented

The implementation follows established distinctions in the primary tool
documentation:

- [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)
  and [flow-state modeling](https://codeql.github.com/docs/codeql-language-guides/using-flow-labels-for-precise-data-flow-analysis/)
  distinguish sources, sinks, path steps, state, and barriers;
- [Semgrep taint concepts](https://semgrep.dev/docs/writing-rules/glossary)
  distinguish sources, sinks, propagators, and sanitizers;
- [Joern data-flow](https://docs.joern.io/cpgql/data-flow-steps/) and
  [control-flow](https://docs.joern.io/cpgql/control-flow-steps/) keep flows,
  dominance, and control dependence separate from generic reachability;
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
  provides stable result identities, provenance, and code-flow structures.

The Phase 0 promotion contract requires an observed external source, a typed
security sink, a matching flow, current line-pinned evidence, checked coverage,
and an exact sink-matched dominating control assessment. Missing or ambiguous
evidence is inconclusive. An effective matching control contradicts the
hypothesis. Only publishable supported hypotheses may enter `Validate next` or
affect the verdict.

The owner projection groups supported traces by stable root cause, folds traces
linked to a direct finding into that direct action, expands at most five fix
groups and three validation groups, and retains all raw facts in the technical
appendix and `report.json`.

## Synthetic contract harness

`benchmarks/report-v1-ground-truth.json` is a fixture-expectation contract. Its
builder deliberately creates normalized graph nodes, flows, controls, evidence,
and direct-finding contexts from those expectations. It therefore exercises
correlation, promotion, grouping, and projection behavior **after extraction**.
It does not exercise source discovery, sink discovery, route discovery, graph
construction from source, candidate generation independence, or real scanner
validation.

The two fixture partitions are named `development` and `synthetic-holdback`.
The latter is a regression holdback only; it is not a research held-out set.
Ratios emitted by this harness describe behavior on constructed contract cases
and must not be published as detection precision, detection recall, baseline
comparison, or generalization evidence.

Three Phase 0 policy compositions were inspected over the same constructed
candidates: permissive edge promotion, strict promotion, and strict promotion
plus semantic publication grouping. Their differences show which contract
mechanism suppresses a known fixture failure. They are not materially different
candidate generators and do not constitute the Phase 1 approach comparison.

Likewise, the guard, sink-type, evidence-freshness, grouping, and connected-flow
ablations are unit-level mechanism checks. They justify retaining defensive
contract assertions, not selecting a detector.

## Reproduce Phase 0

```bash
pnpm benchmark:report-v1
pnpm exec vitest run tests/report-v1-benchmark.test.ts
```

The output is explicitly classified as `synthetic_contract_regression`. It
contains no hard-coded claim of model independence, repository independence,
or recall preservation.

## Boundary before Phase 1

No Phase 0 number may satisfy a Phase 1 capability gate. Phase 1 scanners receive
only a raw Git snapshot. Ground truth is available only to the separate scorer.
VibeShield, CodeQL, Semgrep, and direct Joern queries must each perform their own
extraction, graph construction, candidate generation, and validation on the same
snapshot. Detection is selected only after external corpora, untouched held-out
full scans, real vulnerable/fixed pairs, and independently verified findings are
scored under the preregistered policy.
