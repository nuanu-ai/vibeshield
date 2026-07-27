# CWE-78 Flow-Chain Experiment Termination Record

Status: **terminated as unsuccessful**
Decision date: 2026-07-27

## Objective

The experiment attempted to produce a reusable JavaScript/TypeScript detector
for the following security chain:

`HTTP-controlled input -> inter-file flow -> dynamic dispatch/callback -> command configuration -> process launch inside a dependency`

Success required a deterministic, line-pinned result on Flowise, no result on
its fixed version, and transfer to a previously unseen real vulnerable/fixed
pair without repository-specific coupling.

## Work performed

- Stock and expanded CodeQL flows were evaluated as deterministic baselines.
  Their union confirmed TTS API but missed the Flowise chain in raw output.
- A standalone capability-based analyzer was implemented. It included a custom
  TypeScript CFG/SSA layer, HTTP-source recognition, module and workspace
  resolution, dynamic registry/callback reconstruction, lockfile-bound npm
  dependency inspection, process-effect derivation, validator/barrier handling,
  line-pinned evidence, and deterministic replay.
- Several open adversarial suites and safe counterexamples were constructed.
- A blind real pair based on n8n was frozen for Candidate 4. A later 9router
  vulnerable/fixed pair was materialized for another held-out attempt but was
  never evaluated.

## What was demonstrated

- Candidate 6 produced one Flowise tuning finding from the HTTP controller to
  the actual process launch inside `@modelcontextprotocol/sdk`.
- The normalized Flowise path contained 98 evidence nodes across 17 files,
  including eight dependency nodes.
- The same candidate produced zero findings on the known fixed Flowise
  snapshot.
- Candidate 4 produced zero findings in 20 executions over ten safe
  counterexamples, and all 20 external replays completed.
- Useful research ideas were identified:
  - derive process capabilities from dependency source rather than only from a
    fixed sink-name catalog;
  - represent dynamic registry and callback edges explicitly;
  - retain line-pinned provenance and replayable evidence;
  - model a security fix as a barrier on the same attack path.

These results are tuning and proof-of-concept evidence only.

## What was not demonstrated

- No candidate passed a previously unseen real vulnerable/fixed pair.
- Candidate 4 failed both real n8n executions before producing an artifact
  because one unrelated JavaScript file caused a repository-wide parse abort.
- The later 9router pair has no evaluation or scoring artifact and therefore
  contributes no evidence.
- Candidate 6 was not accepted by a blind transfer test.
- The final open suite had 505 tests: 451 passed and 54 failed.
- No defensible held-out precision, recall, or competitiveness claim was
  established.

## Why the branch was abandoned

The implementation reached 20,057 lines of analyzer/runtime source and 13,074
lines of tests for one CWE family and one narrow attack-chain shape. It grew to
model TypeScript compilation, Gulp asset copying, CommonJS module completion,
runtime directory loaders, registry identity, heap mutation, dependency
factories, and many JavaScript aliasing variants.

Although target names and repository identifiers were not hard-coded, the
implementation increasingly encoded the structural shapes of the disclosed
Flowise and n8n examples. Each new audit generated another large set of
special-case failures, while transfer to an unseen real project remained
unproven. The cost and complexity were therefore disproportionate to the
demonstrated detection value.

The experiment is classified as **semantic overfitting with useful isolated
ideas, but no reusable detector winner**.

## Decision and retention policy

- The capability-based analyzer must not be resumed, integrated into the
  VibeShield pipeline, or cited as evidence of detection accuracy.
- Its implementation, tests, cloned corpora, caches, container artifacts, and
  raw local runs are intentionally deleted rather than retained as dormant
  project surface.
- Only the lessons listed above may inform a future architecture. Reusing the
  abandoned implementation requires a new explicit decision and new
  independent evidence.
- Future research should prefer small falsifiable candidates, existing
  analysis engines, hypothesis-driven attack-chain search, and targeted
  deterministic verification over another monolithic JavaScript analyzer.

## Cleanup scope

The cleanup permanently removes the untracked/ignored experiment directories:

- `research/`
- `.local/research/`

These directories occupied approximately 12 GiB locally before deletion and
were not recoverable from Git. This termination record is the retained summary.
