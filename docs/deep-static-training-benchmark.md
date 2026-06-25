# Deep Static Training Benchmark

This benchmark is the current regression gate for the Joern-backed Deep Static
pipeline on training and model repositories. It proves that a run emits
machine-readable hypothesis candidates, supported static hypotheses, no failed
Deep Static coverage, and complete `dependency_usage` coverage when dependency
components exist.

This is an external product benchmark, not detector logic. The scanner must not
special-case WebGoat, Juice Shop, Freeland, or any other benchmark repository.
Failures should expose systemic gaps in Joern extraction, graph construction,
rule coverage, or reporting.

It is not yet a lesson-level recall benchmark. Claiming exhaustive coverage for
WebGoat, Juice Shop, or another intentionally vulnerable app still requires a
ground-truth inventory of lessons/CWEs and a matcher from expected vulnerability
classes to VibeShield findings, static hypotheses, or documented static-analysis
limitations.

## Command

```bash
pnpm benchmark:deep \
  --expect benchmarks/deep-static-training-baseline.json \
  /Users/dmitry/.vibeshield/runs/20260625194251-245a4c68 \
  /Users/dmitry/.vibeshield/runs/20260625213623-574312f3 \
  /Users/dmitry/.vibeshield/runs/20260625164008-81d5eb5a \
  /Users/dmitry/.vibeshield/runs/20260625164510-1cef7e1e \
  /Users/dmitry/.vibeshield/runs/20260625164651-d290e2b7
```

Run the curated ground-truth slice separately. Normal mode allows tracked
`known_gap` items and prints them as the current recall backlog:

```bash
pnpm benchmark:deep \
  --expect benchmarks/deep-static-training-ground-truth.json \
  /Users/dmitry/.vibeshield/runs/20260625194251-245a4c68 \
  /Users/dmitry/.vibeshield/runs/20260625213623-574312f3
```

To keep every known gap as a hard failure when future gaps are added:

```bash
pnpm benchmark:deep \
  --strict-ground-truth \
  --expect benchmarks/deep-static-training-ground-truth.json \
  /Users/dmitry/.vibeshield/runs/20260625194251-245a4c68 \
  /Users/dmitry/.vibeshield/runs/20260625213623-574312f3
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

## Current Baseline

| Stack | Repository | Run | Supported hypotheses | Candidate families | Key coverage |
| --- | --- | --- | ---: | --- | --- |
| Java | WebGoat | `20260625194251-245a4c68` | 616 | `dependency_usage_path=36`, `external_input_to_dangerous_operation=580` | `data_flow` 290/290, `dependency_usage` 36/36, `language_support` checked 496/496 |
| JS/TS | Juice Shop | `20260625213623-574312f3` | 1787 | `dependency_usage_path=31`, `external_input_to_dangerous_operation=1741`, `ci_supply_chain_path=3`, `content_resource_exposure_path=11`, `smart_contract_risk_path=1` | `data_flow` 728/728, `dependency_usage` 12/12, `content_assets` 1067/1067, `smart_contracts` 17/17, `language_support` checked 652/652 |
| JS/TS local | Freeland | `20260625164008-81d5eb5a` | 164 | `external_input_to_dangerous_operation=163`, `ci_supply_chain_path=1` | `data_flow` 62/380, `language_support` checked 635/635 |
| Python | Vulnerable-Flask-App | `20260625164510-1cef7e1e` | 32 | `external_input_to_dangerous_operation=32` | `data_flow` 16/36, `language_support` checked 2/2 |
| Go | go-dvwa | `20260625164651-d290e2b7` | 88 | `dependency_usage_path=82`, `external_input_to_dangerous_operation=6` | `data_flow` 3/3, `dependency_usage` 82/82, `language_support` partial 54/55 due to one PHP file |

The current WebGoat and Juice Shop runs classify generic external-input paths
into sink-specific titles, including `SQL injection path`, `XXE path`, `Path
traversal or file access path`, `Open redirect path`, `Server-side request
forgery path`, `Cross-site scripting path`, `Code execution path`, `IDOR path`,
`CSRF path`, `Access control path`, `Cryptographic weakness path`,
`JWT token trust path`, `Authentication bypass path`, `Password reset path`,
`Credential trust path`, `Two-factor authentication path`, `LLM prompt/tool
trust path`, `Coupon encoding trust path`, `Security misconfiguration path`,
`Anti-automation bypass path`, `Hidden content/resource exposure path`, and
`Smart contract risk path`.

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
- Juice Shop: 36/36 covered, 0 known gaps.

Future `known_gap` entries should be temporary, explicit backlog items and must
fail under `--strict-ground-truth`.

Current Juice Shop inventory audit result:

- default mode passes with 113 challenges across 16 categories; all 16
  categories map to curated ground-truth expectations and 0 categories carry an
  explicit limitation; 2 categories still carry open challenge-level recall gaps;
- `--fail-on-limitations` passes with 0 inventory limitations;
- `--fail-on-gaps` is intentionally red until the remaining challenge-level gaps
  are converted into covered ground-truth expectations.

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

## Next Gate

The next quality gate should continue expanding the curated file into
lesson/CWE-level coverage for WebGoat and challenge-level coverage for Juice
Shop. Each expected item should map to one of:

- a direct Quick Scan finding;
- a supported static hypothesis family;
- a documented limitation when static-only analysis cannot observe the runtime
  behavior.

The goal is to reduce `known_gap` entries and inventory limitations by improving
Joern extraction, graph construction, rule taxonomy, validation logic, and asset
or UI inventory where needed. Challenge gaps in
`benchmarks/deep-static-training-inventory.json` are the current recall backlog;
do not close a gap by adding repository-specific detector behavior.
