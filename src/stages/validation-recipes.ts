import {
  type HypothesisCandidate,
  validateHypothesisCandidates,
} from "../domain/hypothesis-candidate.js";
import {
  type StaticHypothesis,
  validateStaticHypothesisRecords,
} from "../domain/static-hypothesis.js";
import {
  type ValidationRecipe,
  validateValidationRecipes,
  validationRecipeId,
} from "../domain/validation-recipe.js";

export interface ValidationRecipeHint {
  readonly hypothesisId?: string;
  readonly candidateId?: string;
  readonly requiredFixtures?: ReadonlyArray<string>;
  readonly steps?: ReadonlyArray<string>;
  readonly safetyNotes?: ReadonlyArray<string>;
  readonly materializationHints?: ReadonlyArray<string>;
  readonly knownGaps?: ReadonlyArray<string>;
}

export interface ComposeValidationRecipesInput {
  readonly staticHypotheses: ReadonlyArray<StaticHypothesis>;
  readonly candidates: ReadonlyArray<HypothesisCandidate>;
  readonly hints?: ReadonlyArray<ValidationRecipeHint>;
}

interface IndexedValidationRecipeHint extends ValidationRecipeHint {
  readonly index: number;
}

const DEFAULT_SAFETY_NOTES = [
  "Run only in an isolated disposable environment, never against production systems or real customer data.",
  "Use least-privilege credentials and reversible fixture changes only.",
];

export class ValidationRecipeHintError extends Error {
  override readonly name = "ValidationRecipeHintError";
}

export function composeValidationRecipes(input: ComposeValidationRecipesInput): ValidationRecipe[] {
  const candidates = validateHypothesisCandidates(input.candidates);
  const candidateById = new Map(candidates.map((candidate) => [candidate.id, candidate]));
  const staticHypotheses = validateStaticHypothesisRecords(input.staticHypotheses, {
    candidateIds: candidates.map((candidate) => candidate.id),
  });
  const hypothesisById = new Map(staticHypotheses.map((hypothesis) => [hypothesis.id, hypothesis]));
  const hints = validateHints(input.hints ?? [], hypothesisById, candidateById);

  return validateValidationRecipes(
    staticHypotheses
      .filter(
        (hypothesis) =>
          hypothesis.runtimeValidationRequired && hypothesis.status !== "statically_contradicted",
      )
      .map((hypothesis) => recipeFor(hypothesis, candidateById, hints)),
    { hypothesisIds: staticHypotheses.map((hypothesis) => hypothesis.id) },
  );
}

function recipeFor(
  hypothesis: StaticHypothesis,
  candidateById: ReadonlyMap<string, HypothesisCandidate>,
  hints: ReadonlyArray<IndexedValidationRecipeHint>,
): ValidationRecipe {
  const candidate = candidateById.get(hypothesis.candidateId);
  if (candidate === undefined) {
    throw new ValidationRecipeHintError(
      `staticHypothesis ${hypothesis.id} references unknown candidate: ${hypothesis.candidateId}`,
    );
  }

  const matchedHints = matchingHints(hints, hypothesis, candidate);
  const requiredFixtures = uniqueSorted([
    ...candidate.requiredValidation,
    ...matchedHints.flatMap((hint) => hint.requiredFixtures ?? []),
  ]);
  const materializationHints = uniqueSorted([
    `candidate:${candidate.id}`,
    `family:${candidate.family}`,
    `rule:${candidate.ruleId}`,
    ...candidate.findingIds.map((findingId) => `finding:${findingId}`),
    ...matchedHints.flatMap((hint) => hint.materializationHints ?? []),
  ]);
  const knownGaps = uniqueSorted([
    ...(hypothesis.status === "inconclusive" ? [hypothesis.pathSummary] : []),
    ...matchedHints.flatMap((hint) => hint.knownGaps ?? []),
  ]);

  return {
    id: validationRecipeId(hypothesis.id),
    hypothesisId: hypothesis.id,
    requiredFixtures,
    steps: uniqueStable([
      ...defaultSteps(hypothesis, requiredFixtures),
      ...matchedHints.flatMap((hint) => hint.steps ?? []),
    ]),
    expectedResult: expectedResultFor(hypothesis),
    safetyNotes: uniqueStable([
      ...DEFAULT_SAFETY_NOTES,
      ...matchedHints.flatMap((hint) => hint.safetyNotes ?? []),
    ]),
    materializationHints,
    knownGaps,
  };
}

function matchingHints(
  hints: ReadonlyArray<IndexedValidationRecipeHint>,
  hypothesis: StaticHypothesis,
  candidate: HypothesisCandidate,
): IndexedValidationRecipeHint[] {
  return hints.filter(
    (hint) => hint.hypothesisId === hypothesis.id || hint.candidateId === candidate.id,
  );
}

function defaultSteps(
  hypothesis: StaticHypothesis,
  requiredFixtures: ReadonlyArray<string>,
): string[] {
  return [
    `Prepare isolated runtime fixtures: ${requiredFixtures.join(", ")}.`,
    `Replay the static path described by hypothesis ${hypothesis.id} against a disposable environment.`,
    "Record whether the expected protection blocks the impact without changing production data.",
  ];
}

function expectedResultFor(hypothesis: StaticHypothesis): string {
  switch (hypothesis.status) {
    case "statically_supported":
      return "Future runtime validation should gather controlled evidence for or against the statically supported path; this recipe does not claim runtime confirmation.";
    case "inconclusive":
      return "Future runtime validation should determine whether the unobserved control exists on the analyzed path; this recipe does not claim runtime confirmation.";
    case "candidate":
      return "Future runtime validation should prove or disprove this candidate before remediation priority changes; this recipe does not claim runtime confirmation.";
    case "statically_contradicted":
      throw new ValidationRecipeHintError(
        `statically contradicted hypothesis ${hypothesis.id} cannot produce a recipe`,
      );
  }
}

function validateHints(
  hints: ReadonlyArray<ValidationRecipeHint>,
  hypothesisById: ReadonlyMap<string, StaticHypothesis>,
  candidateById: ReadonlyMap<string, HypothesisCandidate>,
): IndexedValidationRecipeHint[] {
  return hints.map((hint, index) => validateHint(hint, index, hypothesisById, candidateById));
}

function validateHint(
  hint: ValidationRecipeHint,
  index: number,
  hypothesisById: ReadonlyMap<string, StaticHypothesis>,
  candidateById: ReadonlyMap<string, HypothesisCandidate>,
): IndexedValidationRecipeHint {
  if (hint.hypothesisId === undefined && hint.candidateId === undefined) {
    fail(`validationRecipeHint ${index} requires hypothesisId or candidateId`);
  }
  if (!hasPayload(hint)) {
    fail(`validationRecipeHint ${index} requires at least one recipe field`);
  }

  const hypothesis =
    hint.hypothesisId === undefined
      ? undefined
      : knownTarget(hint.hypothesisId, hypothesisById, `hypothesisId`, index);
  const candidate =
    hint.candidateId === undefined
      ? undefined
      : knownTarget(hint.candidateId, candidateById, `candidateId`, index);

  if (
    hypothesis !== undefined &&
    candidate !== undefined &&
    hypothesis.candidateId !== candidate.id
  ) {
    fail(
      `validationRecipeHint ${index} hypothesis ${hypothesis.id} does not match candidate ${candidate.id}`,
    );
  }

  assertOptionalNonEmptyList(hint.requiredFixtures, `validationRecipeHint ${index} fixtures`);
  assertOptionalNonEmptyList(hint.steps, `validationRecipeHint ${index} steps`);
  assertOptionalNonEmptyList(hint.safetyNotes, `validationRecipeHint ${index} safetyNotes`);
  assertOptionalNonEmptyList(
    hint.materializationHints,
    `validationRecipeHint ${index} materializationHints`,
  );
  assertOptionalNonEmptyList(hint.knownGaps, `validationRecipeHint ${index} knownGaps`);

  return { ...hint, index };
}

function knownTarget<T>(
  id: string,
  recordsById: ReadonlyMap<string, T>,
  label: string,
  index: number,
): T {
  assertNonEmpty(id, `validationRecipeHint ${index} ${label}`);
  const record = recordsById.get(id);
  if (record === undefined) {
    fail(`validationRecipeHint ${index} references unknown ${label}: ${id}`);
  }
  return record;
}

function hasPayload(hint: ValidationRecipeHint): boolean {
  return (
    hasValues(hint.requiredFixtures) ||
    hasValues(hint.steps) ||
    hasValues(hint.safetyNotes) ||
    hasValues(hint.materializationHints) ||
    hasValues(hint.knownGaps)
  );
}

function hasValues(values: ReadonlyArray<string> | undefined): boolean {
  return values !== undefined && values.length > 0;
}

function assertOptionalNonEmptyList(
  values: ReadonlyArray<string> | undefined,
  label: string,
): void {
  if (values === undefined) {
    return;
  }
  if (values.length === 0) {
    fail(`${label} are required`);
  }
  for (const value of values) {
    assertNonEmpty(value, label);
  }
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    fail(`${label} is required`);
  }
}

function uniqueStable(values: ReadonlyArray<string>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    if (!seen.has(value)) {
      seen.add(value);
      out.push(value);
    }
  }
  return out;
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

function fail(message: string): never {
  throw new ValidationRecipeHintError(message);
}
