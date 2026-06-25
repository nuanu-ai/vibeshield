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
  /Users/dmitry/.vibeshield/runs/20260625175941-5634a440 \
  /Users/dmitry/.vibeshield/runs/20260625184641-02d6d398 \
  /Users/dmitry/.vibeshield/runs/20260625164008-81d5eb5a \
  /Users/dmitry/.vibeshield/runs/20260625164510-1cef7e1e \
  /Users/dmitry/.vibeshield/runs/20260625164651-d290e2b7
```

Run the curated ground-truth slice separately. Normal mode allows tracked
`known_gap` items and prints them as the current recall backlog:

```bash
pnpm benchmark:deep \
  --expect benchmarks/deep-static-training-ground-truth.json \
  /Users/dmitry/.vibeshield/runs/20260625175941-5634a440 \
  /Users/dmitry/.vibeshield/runs/20260625184641-02d6d398
```

To turn every known gap into a hard failure:

```bash
pnpm benchmark:deep \
  --strict-ground-truth \
  --expect benchmarks/deep-static-training-ground-truth.json \
  /Users/dmitry/.vibeshield/runs/20260625175941-5634a440 \
  /Users/dmitry/.vibeshield/runs/20260625184641-02d6d398
```

## Current Baseline

| Stack | Repository | Run | Supported hypotheses | Candidate families | Key coverage |
| --- | --- | --- | ---: | --- | --- |
| Java | WebGoat | `20260625175941-5634a440` | 258 | `external_input_to_dangerous_operation=258` | `data_flow` 129/222, `language_support` checked 496/496 |
| JS/TS | Juice Shop | `20260625184641-02d6d398` | 773 | `external_input_to_dangerous_operation=770`, `ci_supply_chain_path=3` | `data_flow` 333/333, `language_support` checked 652/652 |
| JS/TS local | Freeland | `20260625164008-81d5eb5a` | 164 | `external_input_to_dangerous_operation=163`, `ci_supply_chain_path=1` | `data_flow` 62/380, `language_support` checked 635/635 |
| Python | Vulnerable-Flask-App | `20260625164510-1cef7e1e` | 32 | `external_input_to_dangerous_operation=32` | `data_flow` 16/36, `language_support` checked 2/2 |
| Go | go-dvwa | `20260625164651-d290e2b7` | 88 | `dependency_usage_path=82`, `external_input_to_dangerous_operation=6` | `data_flow` 3/3, `dependency_usage` 82/82, `language_support` partial 54/55 due to one PHP file |

The current WebGoat and Juice Shop runs classify generic external-input paths
into sink-specific titles, including `SQL injection path`, `XXE path`, `Path
traversal or file access path`, `Open redirect path`, `Server-side request
forgery path`, `Cross-site scripting path`, `Code execution path`, `IDOR path`,
`CSRF path`, and `Access control path`.

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

Current normal result on the latest WebGoat and Juice Shop runs:

- WebGoat: 10/12 covered, 2 known gaps.
- Juice Shop: 16/17 covered, 1 known gap.

Current strict result intentionally fails until those known gaps are resolved.

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
lesson/CWE-level coverage for WebGoat and Juice Shop. Each expected item should
map to one of:

- a direct Quick Scan finding;
- a supported static hypothesis family;
- a documented limitation when static-only analysis cannot observe the runtime
  behavior.

The goal is to reduce `known_gap` entries by improving Joern extraction, graph
construction, rule taxonomy, and validation logic. Do not close a gap by adding
repository-specific detector behavior.
