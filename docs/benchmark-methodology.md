# Benchmark Methodology

This document is the measurement contract for improving VibeShield detection
quality. It applies to both R&D phases:

- **Phase 1, capability:** reach the target metrics on the benchmark. Cost,
  latency, stack size, and CLI compactness are not optimization constraints in
  this phase.
- **Phase 2, efficiency:** keep the same benchmark floor while making the system
  cheaper, faster, smaller, and closer to the engineering constraints in
  [architecture.md](architecture.md).

Phase 1 freedom applies only to engineering optimization. It does not relax
validity constraints: scanned repositories are still untrusted input, scanner
and graph facts remain deterministic, the model cannot become the source of
truth, and benchmark improvements must not be repository-specific patches.

## Operating Loop

Every improvement cycle follows the same order:

```text
measure -> pick the highest-impact gap -> research solution options ->
spike -> measure benchmark delta -> promote or reject -> next gap
```

R&D is not a separate "go search for better tools" phase. It is a decision aid
inserted after a measured gap is known and before a solution is chosen. Internet
research, papers, tool docs, public benchmarks, and existing analyzers are useful
only when they answer a specific gap question, such as:

- how to close a Python SSRF graph/projection gap without repository-specific
  behavior;
- how to reduce JS dependency false positives with reachability evidence;
- how to validate Go command-injection support without creating false support;
- which analyzer gives the best source-to-sink evidence for a language/class.

## Work Order

### 1. Build the measurement loop

Goal: get an honest way to say where VibeShield is today.

Do:

- fix the benchmark matrix: WebGoat, Juice Shop, Vulnerable-Flask-App, and
  go-dvwa;
- pin origin, commit, tool versions, and vulnerability database freshness;
- curate ground truth for every scored repository;
- keep Freeland as a canary/regression target, not a precision/recall source;
- write the scorer over `report.json`.

Check:

- the same snapshot produces reproducible output;
- ground truth is not derived from VibeShield output;
- Python and Go do not enter scored precision/recall until their truth is
  curated;
- the scorer emits TP, FP, FN, true-but-uncurated, coverage loss,
  precision/recall/F0.5, candidate recall, support precision, false
  contradiction, and verdict correctness.

Done: the first honest baseline table exists.

### 2. Run the baseline without detector changes

Goal: learn the current state without mixing measurement and improvement.

Do:

- run the pinned matrix on the current code;
- keep reports, manifests, and scorer output;
- break down results per language and per CWE or vulnerability class.

Check: TP, FP, FN, false support, false contradiction, coverage exclusions, and
wrong verdicts are visible.

Done: there is a concrete miss/noise list, not just "improve accuracy."

### 3. Attribute every failure

Goal: identify the system layer that caused each miss or bad claim.

Use these buckets:

- `extraction-gap`: the backend did not extract the needed facts;
- `graph/projection-gap`: facts exist, but the graph did not connect them;
- `rule-taxonomy-gap`: a rule, family, or classification is missing;
- `validation-gap`: `supported`, `contradicted`, or `inconclusive` is wrong;
- `reporting/dedup-gap`: evidence exists, but grouping or reporting is wrong;
- `scanner-noise`: a direct scanner-backed finding is noise;
- `coverage-loss`: the relevant area was not visible to the tooling.

Done: the backlog is made of systemic gap classes, not one-off benchmark cases.

### 4. Pick the next gap by impact

Goal: work on one decision-quality problem at a time.

Prefer gaps that:

- move the verdict;
- create many false Fix Pack actions;
- cut recall in a required language;
- lower support precision;
- repeat across repositories, languages, or classes;
- block a fair coverage denominator.

Done: the next cycle has one engineering question.

### 5. Run R&D before choosing the solution

Goal: choose the most likely way to move the measured metric.

Write a short solution brief:

- the gap being closed;
- the metric expected to move;
- 2-4 approaches or tools;
- relevant evidence from docs, papers, repositories, or public benchmarks;
- expected TP/FP/FN effect;
- integration cost;
- overfit risk;
- the smallest spike that can prove or disprove the approach.

Done: the choice is evidence-backed, not tool-fashion-driven.

### 6. Spike before product integration

Goal: test the hypothesis quickly.

Phase 1 may use heavier technology: CodeQL, Semgrep, language analyzers, taint
engines, dependency reachability, custom parsers, extra vulnerability databases,
or graph pipelines. A spike must still:

- run isolated from untrusted repositories;
- avoid starting the scanned app;
- produce file/path/line/class evidence;
- be deterministic on pinned inputs;
- avoid repository-specific behavior;
- compare against the pinned benchmark.

Done: the spike has a benchmark delta, not just a plausible architecture.

### 7. Accept or reject by metrics

Keep the approach only when:

- precision improves or false positives drop;
- recall does not regress beyond the accepted tolerance;
- support precision improves or holds;
- held-out validation does not show overfit;
- evidence can be explained in the report;
- coverage states remain truthful;
- the improvement is systemic, not tied to one repository.

Reject it when it:

- improves tuning but not held-out;
- reduces false positives by hiding recall collapse;
- produces unsupported statuses;
- requires the model to be the source of truth;
- breaks isolation or determinism.

Done: only measured improvements enter the product path.

### 8. Promote a successful spike

Goal: turn an experiment into a supported VibeShield layer.

Do:

- normalize contracts;
- add stages or adapters;
- add tests;
- update coverage reporting;
- update docs;
- add benchmark expectations;
- remove experiment-only shortcuts.

Check: relevant tests, typecheck/lint, `pnpm benchmark:deep`, scorer delta, no
repository-specific logic, and truthful report wording.

Done: the improvement is part of the pipeline, not a manual experiment.

### 9. Validate against overfit

Goal: prove general detection.

Do:

- split the benchmark into tuning and held-out sets;
- keep held-out unseen during detector work;
- run held-out only for validation;
- compare the gap.

Done: tuning vs held-out stays within about 10 percentage points.

### 10. Reach the Phase 1 target

Phase 1 succeeds only when the target table below is met, including per-language
requirements, coverage requirements, verdict correctness, and anti-overfit.

Done: capability is proven by measurement.

### 11. Freeze the Phase 1 floor

Goal: keep the achieved capability from drifting away.

Freeze:

- benchmark manifest;
- scorer output;
- target table;
- accepted technologies;
- known limitations;
- held-out result;
- regression floor.

Done: Phase 2 is not allowed to drop below this floor.

### 12. Optimize in Phase 2

Goal: get the same quality cheaper, faster, and smaller.

Do:

- remove unnecessary tools;
- replace heavy stages with lighter ones where possible;
- cache;
- reduce latency;
- simplify CLI/runtime shape;
- reduce model and tool cost.

Every simplification is checked by the same scorer.

Done: the benchmark floor holds with better engineering efficiency.

## What Is Measured

VibeShield output has three different surfaces, so one aggregate score would be
misleading.

| Surface | Unit | Metric shape |
| --- | --- | --- |
| Direct findings | Correlated finding after `findings.correlate` | Precision, recall, F0.5 |
| Static hypotheses | Hypothesis within its candidate family | Candidate recall, support precision, false contradiction |
| Coverage | `checked` / `skipped` / `failed` / `degraded` / `partial` plus `language_support` | Gate and report context, not precision/recall |

There is also one repository-level outcome metric: whether the final verdict
matches the curated expectation for deploy-blocking repositories.

Metrics must be reported per language and per CWE or vulnerability class before
any aggregate is accepted. An aggregate that hides one weak language or class is
not a success signal.

## Ground Truth

Scored quality is measured only against curated external truth, not against
VibeShield's own output. The scoring spine is:

| Repository | Language | Truth source |
| --- | --- | --- |
| WebGoat | Java | Lessons mapped to classes or CWE |
| Juice Shop | JS/TS | `data/static/challenges.yml` and vulnerable-code markers |
| Vulnerable-Flask-App | Python | Vulnerability classes documented by the app |
| go-dvwa | Go | README-documented SQLi, shell injection, NoSQL injection, and SSRF |

Python and Go repositories with duplicate names must be pinned by origin and
commit in the benchmark manifest. Ground truth is valid only for the pinned
snapshot.

Freeland is not part of scored precision/recall. It is a real local JS/TS
canary for run stability, determinism, coverage quality, and manual triage of
true-but-uncurated findings. Its unknown vulnerability set makes precision and
recall claims invalid.

Current curated expectations exist for WebGoat and Juice Shop. The first
methodology gate is to extend curated ground truth to Vulnerable-Flask-App and
go-dvwa before claiming Python or Go precision/recall.

Each scored repository needs two expectation sets:

- expected direct findings: class or CWE, location, surface, `inStaticScope`,
  and coverage area;
- expected supported hypotheses: candidate family, class or CWE, source-to-sink
  path, `inGraphScope`, and coverage area.

Runtime-only, behavioral, business-logic, or OSINT expectations stay in the
truth inventory but are excluded from the static recall denominator with
`inStaticScope: false`. Real weaknesses found by VibeShield that are absent from
the curated truth are recorded as `true-but-uncurated`, not counted as false
positives.

## Metrics

Direct findings are scored after correlation and deduplication:

- **TP:** a correlated finding matches curated truth by class and location.
- **FP:** a finding matches neither curated truth nor true-but-uncurated review.
- **FN:** an in-scope curated item has no matching finding.
- **Precision:** `TP / (TP + FP)`.
- **Recall:** `TP / (TP + FN)` for `inStaticScope` items in `checked` coverage.
- **F0.5:** the summary scalar, because false Fix Pack actions are more costly
  than misses for report trust.

Static hypotheses use separate measures:

- **Candidate recall:** share of curated attack paths, in non-failed graph
  coverage, that emit a candidate of the expected family.
- **Support precision:** share of `statically_supported` hypotheses that map to
  a real reachable path.
- **False contradiction:** real paths marked `statically_contradicted`.
  `inconclusive` is not counted as an error.

Coverage gates the denominator for direct findings and hypotheses. A missed item
inside failed or partial coverage is not charged as recall loss, but the coverage
loss is reported separately in limitations.

Verdict scoring checks that every curated deploy-blocking repository is reported
as `not-ready-to-deploy`, and that a scan never returns a green verdict when
required Quick Scan coverage is lost.

## Baseline Procedure

A baseline measures the current system before detector changes.

1. Pin repository origin, commit, tool versions, vulnerability database
   freshness, and relevant artifact hashes in a manifest.
2. Run the full benchmark matrix with those pinned inputs.
3. Map `report.json` output to ground truth and separate TP, FP, FN,
   true-but-uncurated, and coverage loss.
4. Attribute every miss or bad match to a systemic cause:
   `extraction-gap`, `graph/projection-gap`, `rule-taxonomy-gap`,
   `validation-gap`, `reporting/dedup-gap`, `scanner-noise`, or
   `coverage-loss`.
5. Freeze the baseline table with precision, recall, F0.5, static-hypothesis
   metrics, coverage summary, and verdict correctness.

Only deltas from this frozen table count as improvement.

## Targets

These targets are the Phase 1 success criteria and the Phase 2 regression floor.
They apply per language for JS/TS, Python, Go, and Java.

| Surface | Metric | Target |
| --- | --- | --- |
| Direct findings | Precision | >= 0.90 on published Fix Pack findings |
| Direct findings | Recall | >= 0.85 of in-static-scope curated truth |
| Static hypotheses | Support precision | >= 0.80 |
| Static hypotheses | Candidate recall | >= 0.80 of curated attack paths in coverage |
| Coverage | Deep Static | No `failed`; complete dependency usage where dependencies exist |
| Coverage | Mixed language | Accurate `language_support` partial/degraded reporting |
| Verdict | Deploy-blocking repos | 100% `not-ready-to-deploy` |
| Anti-overfit | Tuning vs held-out | Gap <= about 10 percentage points |

Targets can be recalibrated after the first scored baseline, but anything that
can affect verdict trust must not be weakened silently.

## Validity Rules

Benchmark runs are useful only when they test general detection.

- Do not add repository-specific detector behavior to make benchmark runs pass.
- Split the matrix into tuning and held-out sets. Held-out repositories are not
  inspected during detector work; they are run only for validation.
- Treat cross-language transfer as an overfit check. A change that helps one
  repository or one language without a systemic explanation is suspect.
- Compare runs only when repository snapshots, tool versions, and vulnerability
  database freshness match the manifest.
- Use deterministic graph ids, hypothesis ids, and ordering so metric movement
  is real change, not run noise.
- Diagnose misses by system layer rather than adding one-off rules for a
  repository.

`pnpm benchmark:deep` and `pnpm benchmark:inventory` are regression gates on the
Deep Static training matrix. `pnpm benchmark:score` is the scored Phase 1
measurement surface. It must fail target gates while curated truth or FP/support
review is incomplete; passing it is meaningful only after the scored truth file
is complete enough to make every target metric scoreable.
