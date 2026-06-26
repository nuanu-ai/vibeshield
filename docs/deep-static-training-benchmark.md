# Deep Static Training Benchmark

This benchmark is the current regression gate for the Joern-backed Deep Static
lane on training and model repositories. It proves that a run emits
machine-readable hypothesis candidates, supported static hypotheses, no failed
Deep Static coverage, and complete `dependency_usage` coverage when dependency
components exist.

This is a regression gate for one product lane, not the final scored quality
result for VibeShield as a whole. The broader family-based benchmark,
precision/recall methodology, targets, anti-overfit rules, and Phase 1/Phase 2
contract live in [benchmark-methodology.md](benchmark-methodology.md). The first
scored harness is `pnpm benchmark:score`; it intentionally fails target gates
until curated truth and FP/support review are complete enough to calculate the
metrics.

This is also an external product benchmark, not detector logic. The scanner must
not special-case WebGoat, Juice Shop, Freeland, or any other benchmark
repository. Failures should expose systemic gaps in Joern extraction, graph
construction, rule coverage, validation, or reporting.

The scored harness is not yet an achieved TP/FP/FN benchmark. Claiming
precision, recall, or exhaustive Deep Static coverage for WebGoat, Juice Shop,
Vulnerable-Flask-App, go-dvwa, or another intentionally vulnerable app still
requires pinned curated truth, static-detectability markings, complete
FP/support review, coverage-aware denominators, and matchers from expected
vulnerability classes to VibeShield findings or static hypotheses. Claiming the
overall product target additionally requires scored lanes for secrets,
dependencies, CI/CD, IaC/config, deterministic code patterns, coverage, and
verdict behavior.

When generating fresh benchmark reports, use `--no-model` or
`VIBESHIELD_NO_MODEL=1` so optional OpenRouter wording cannot slow or perturb the
measurement run:

```bash
pnpm scan /tmp/vibeshield-score-src/Vulnerable-Flask-App --deep --no-model
```

The OSV dependency scanner runs with IPv4-first DNS ordering so benchmark runs
stay reproducible on hosts where IPv6 egress is unavailable.

## Command

```bash
pnpm benchmark:deep \
  --expect benchmarks/deep-static-training-baseline.json \
  /Users/dmitry/.vibeshield/runs/20260626112711-237f9ec7 \
  /Users/dmitry/.vibeshield/runs/20260626112812-9d82f57e \
  /Users/dmitry/.vibeshield/runs/20260625164008-81d5eb5a \
  /Users/dmitry/.vibeshield/runs/20260626082052-aa2c42be \
  /Users/dmitry/.vibeshield/runs/20260626084326-6cff1ffd
```

Run the curated ground-truth slice separately. Normal mode allows tracked
`known_gap` items and prints them as the current recall backlog:

```bash
pnpm benchmark:deep \
  --expect benchmarks/deep-static-training-ground-truth.json \
  /Users/dmitry/.vibeshield/runs/20260626112711-237f9ec7 \
  /Users/dmitry/.vibeshield/runs/20260626112812-9d82f57e
```

To keep every known gap as a hard failure when future gaps are added:

```bash
pnpm benchmark:deep \
  --strict-ground-truth \
  --expect benchmarks/deep-static-training-ground-truth.json \
  /Users/dmitry/.vibeshield/runs/20260626112711-237f9ec7 \
  /Users/dmitry/.vibeshield/runs/20260626112812-9d82f57e
```

Audit the Juice Shop challenge inventory separately. This checks that every
challenge category in `data/static/challenges.yml` is either mapped to one or
more curated ground-truth expectations or is explicitly documented as a static
analysis limitation:

```bash
pnpm benchmark:inventory \
  --source juice-shop=/tmp/vibeshield-juice-shop-probe
```

Use the stricter inventory mode when evaluating whether the current benchmark is
ready to claim category-level completeness:

```bash
pnpm benchmark:inventory \
  --fail-on-limitations \
  --source juice-shop=/tmp/vibeshield-juice-shop-probe
```

Use the challenge-gap mode when evaluating whether the current benchmark is
ready to claim challenge-level recall completeness:

```bash
pnpm benchmark:inventory \
  --fail-on-gaps \
  --source juice-shop=/tmp/vibeshield-juice-shop-probe
```

Run the scored harness against the same pinned reports. This command is the
Phase 1 measurement surface for TP/FP/FN-style targets. It is expected to fail
until the scored truth file is complete:

```bash
pnpm benchmark:score \
  /Users/dmitry/.vibeshield/runs/20260626112711-237f9ec7 \
  /Users/dmitry/.vibeshield/runs/20260626112812-9d82f57e \
  /Users/dmitry/.vibeshield/runs/20260626082052-aa2c42be \
  /Users/dmitry/.vibeshield/runs/20260626084326-6cff1ffd
```

Use the static support review helper before changing `staticTruth` or
`staticSupportReview` completeness. It shows which supported hypotheses are
already consumed by scored truth or true-but-uncurated buckets and groups the
remaining review queue by family/title with sample evidence:

```bash
pnpm benchmark:score-review \
  /Users/dmitry/.vibeshield/runs/20260626112711-237f9ec7 \
  /Users/dmitry/.vibeshield/runs/20260626112812-9d82f57e \
  /Users/dmitry/.vibeshield/runs/20260626082052-aa2c42be \
  /Users/dmitry/.vibeshield/runs/20260626084326-6cff1ffd
```

## Current Baseline

| Stack | Repository | Run | Supported hypotheses | Candidate families | Key coverage |
| --- | --- | --- | ---: | --- | --- |
| Java | WebGoat | `20260626112711-237f9ec7` | 310 | `dependency_usage_path=1`, `external_input_to_dangerous_operation=309` | `data_flow` 352/352, `dependency_usage` 36/36, `language_support` checked 496/496 |
| JS/TS | Juice Shop | `20260626112812-9d82f57e` | 432 | `dependency_usage_path=7`, `external_input_to_dangerous_operation=408`, `ci_supply_chain_path=3`, `content_resource_exposure_path=13`, `smart_contract_risk_path=1` | `data_flow` 527/527, `dependency_usage` 12/12, `content_assets` 1067/1067, `smart_contracts` 17/17, `language_support` checked 652/652 |
| JS/TS local | Freeland | `20260625164008-81d5eb5a` | 164 | `external_input_to_dangerous_operation=163`, `ci_supply_chain_path=1` | `data_flow` 62/380, `language_support` checked 635/635 |
| Python | Vulnerable-Flask-App | `20260626082052-aa2c42be` | 24 | `external_input_to_dangerous_operation=24` | `data_flow` 24/36, `language_support` checked 2/2 |
| Go | go-dvwa | `20260626084326-6cff1ffd` | 3 | `dependency_usage_path=1`, `external_input_to_dangerous_operation=2` | `data_flow` 3/3, `dependency_usage` 1/1, `language_support` partial 54/55 due to one PHP file |

The current WebGoat and Juice Shop rows are post-semantic-dedup reports: they
keep the curated ground-truth slice covered while reducing the supported
hypothesis review queue from 674 to 310 for WebGoat and from 1797 to 432 for
Juice Shop. Dependency usage paths now merge duplicate advisory-specific
component paths into one semantic component-use hypothesis while retaining the
linked direct finding ids, and LLM trust classification ignores unrelated LLM
config/retry/error assignments. Generic static or environment-configured
outbound HTTP calls remain graph sinks but no longer promote to deploy-blocking
external-input attack-path hypotheses. Hypothesis titles now follow the reached
sink semantics instead of allowing benchmark route or lesson names to relabel
unrelated sinks; WebGoat account-recovery flows are represented as
`password_reset_trust` sinks in the graph instead of relying on title rewriting.
Generic JWT decode/verify/sign helpers no longer become `jwt_token_trust` sinks
unless the surrounding context exposes explicit JWT challenge or weak-token
semantics, and coupon encoding sinks require coupon/Z85/discount context rather
than any generic decode in a shared security helper.
CSRF state-change sinks require explicit CSRF context or browser
cookie/session context, so ordinary JSON or bearer-token API mutations no longer
become CSRF attack-path hypotheses only because they call `push`, `update`,
`write`, `create`, or similar mutators.

The current WebGoat and Juice Shop runs classify generic external-input paths
into sink-specific titles, including `SQL injection path`, `XXE path`, `Path
traversal or file access path`, `Log disclosure path`, `Open redirect path`,
`Server-side request forgery path`, `Cross-site scripting path`, `Code execution
path`, `IDOR path`, `CSRF path`, `Access control path`, `Cryptographic weakness
path`, `JWT token trust path`, `Authentication bypass path`, `Password reset
path`, `Credential trust path`, `Two-factor authentication path`,
`LLM prompt/tool trust path`, `Coupon encoding trust path`,
`Security misconfiguration path`, `Anti-automation bypass path`,
`Hidden content/resource exposure path`, and `Smart contract risk path`.

This baseline intentionally remains a Deep Static/taint-heavy slice. It is not
evidence that the full VibeShield product benchmark is covered, because it does
not exercise the secrets, dependency, CI/CD, IaC/config, deterministic-pattern,
and deploy-verdict lanes with their own clean truth oracles.

## Expectation Files

The checked-in regression baseline lives at
`benchmarks/deep-static-training-baseline.json`. It matches reports by GitHub
origin URL or local path suffix and checks minimum counts for findings,
supported hypotheses, candidate families, and coverage. These thresholds prevent
silent regression; they do not prove that the benchmark repositories are fully
covered.

The initial curated ground-truth slice lives at
`benchmarks/deep-static-training-ground-truth.json`. It records expected
vulnerability classes for WebGoat and Juice Shop as either:

- `covered`: the current report must contain a matching direct finding, static
  hypothesis, family count, coverage entry, or limitation;
- `known_gap`: the expected class is intentionally tracked as missing or too
  generic today. Normal benchmark output shows it as a known gap; passing
  `--strict-ground-truth` turns it into a hard failure.

Current normal and strict results on the latest WebGoat and Juice Shop runs:

- WebGoat: 21/21 covered, 0 known gaps.
- Juice Shop: 39/39 covered, 0 known gaps.

Future `known_gap` entries should be temporary, explicit backlog items and must
fail under `--strict-ground-truth`.

These `groundTruth` entries are coverage-style expectations, not scored truth
items. They answer "does the report expose at least one matching signal for this
curated class?" They do not yet compute TP, FP, FN, precision, recall, F0.5,
support precision, false contradiction, or true-but-uncurated buckets.

The scored seed lives at `benchmarks/deep-static-scored-ground-truth.json`. It
contains the four scored repositories and the Phase 1 target values. WebGoat and
Juice Shop now carry the current curated coverage-style static expectations in
the scored truth file: WebGoat scores the current slice at 20/20 candidate
matches and Juice Shop scores 36/36 candidate matches on the pinned runs. Python
and Go include pinned static-truth slices curated from their READMEs and source:
Vulnerable-Flask-App currently scores static candidate recall at 9/9, and
go-dvwa scores 2/2 for the implemented SQL injection and shell injection cases.
WebGoat, Juice Shop, and go-dvwa have complete direct-finding review for the
current scored runs. Python direct truth is complete as an empty direct Quick
Scan denominator for the current report. Java/JS static truth and Java/JS
static-support review are still incomplete until the remaining supported
hypotheses are reviewed as true-but-uncurated or false support, so
`pnpm benchmark:score` reports scoreability failures instead of pretending
support precision or full static recall can already be claimed.

Current Juice Shop inventory audit result:

- default mode passes with 113 challenges across 16 categories; all 16
  categories map to curated ground-truth expectations and 0 categories carry an
  explicit limitation; 0 categories carry open challenge-level recall gaps;
- `--fail-on-limitations` passes with 0 inventory limitations;
- `--fail-on-gaps` passes with 0 open challenge-level recall gaps.

Optional `groundTruth` entries are reserved for curated expected vulnerability
classes. They should describe product-observable signals or documented
limitations and must stay outside the scanner runtime.

Supported `groundTruth` matchers:

- `finding`: direct Quick Scan finding by rule/category/remediation key/severity
  and optional file-path substring.
- `hypothesis`: static hypothesis by family/rule/status/title substring and
  optional `candidateReason` substring.
- `family`: minimum count for a static hypothesis family.
- `coverage`: required Deep Static coverage state/count/completeness.
- `limitation`: required documented static-analysis limitation.

Do not add a `groundTruth` entry just because the current run emits it. Add one
only when it comes from a curated benchmark expectation, such as a WebGoat
lesson, Juice Shop challenge, known vulnerable fixture, or an intentionally
documented static-analysis limitation.

## Next Methodology Gate

The next Deep Static quality gate should turn the current regression slice into
the first scored taint/static-hypothesis lane described in
[benchmark-methodology.md](benchmark-methodology.md). It should not be treated as
the full Phase 1 product benchmark.
That means:

- keep WebGoat and Juice Shop scoped to static-detectable classes and reviewed
  supported paths, instead of treating every runtime/business-logic challenge as
  a static recall target;
- use Vulnerable-Flask-App and go-dvwa as held-out taint/injection checks with
  pinned truth and static-detectability markings;
- keep Freeland as a local stability and determinism canary, not a scored
  precision/recall repository;
- complete `benchmarks/deep-static-scored-ground-truth.json` so
  `pnpm benchmark:score` can separate TP, FP, FN, true-but-uncurated, coverage
  loss, and systemic miss causes;
- add separate scored benchmark lanes for secrets, dependencies, CI/CD, and
  IaC/config before using the target table as a product-level success claim.

Each expected item should map to one of:

- a direct Quick Scan finding;
- a supported static hypothesis family;
- a documented limitation when static-only analysis cannot observe the runtime
  behavior.

The goal is to reduce `known_gap` entries and inventory limitations by improving
Joern extraction, graph construction, rule taxonomy, validation logic, and asset
or UI inventory where needed. Challenge gaps in
`benchmarks/deep-static-training-inventory.json` are the current recall backlog;
do not close a gap by adding repository-specific detector behavior.
