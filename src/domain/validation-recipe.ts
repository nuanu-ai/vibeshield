import { securityGraphStableId } from "./security-graph.js";

export interface ValidationRecipe {
  readonly id: string;
  readonly hypothesisId: string;
  readonly requiredFixtures: ReadonlyArray<string>;
  readonly steps: ReadonlyArray<string>;
  readonly expectedResult: string;
  readonly safetyNotes: ReadonlyArray<string>;
  readonly materializationHints: ReadonlyArray<string>;
  readonly knownGaps: ReadonlyArray<string>;
}

export interface ValidationRecipeValidationContext {
  readonly hypothesisIds?: ReadonlySet<string> | ReadonlyArray<string>;
}

export class ValidationRecipeValidationError extends Error {
  override readonly name = "ValidationRecipeValidationError";
}

export function validationRecipeId(hypothesisId: string): string {
  return securityGraphStableId("validation_recipe", [hypothesisId]);
}

export function validateValidationRecipes(
  records: ReadonlyArray<ValidationRecipe>,
  context: ValidationRecipeValidationContext = {},
): ValidationRecipe[] {
  const hypothesisIds =
    context.hypothesisIds === undefined ? undefined : toSet(context.hypothesisIds);
  const seenIds = new Set<string>();
  const seenHypothesisIds = new Set<string>();

  for (const record of records) {
    assertNonEmpty(record.id, "validationRecipe id");
    assertUnique(record.id, seenIds, "validationRecipe id");
    assertNonEmpty(record.hypothesisId, `validationRecipe ${record.id} hypothesisId`);
    assertUnique(record.hypothesisId, seenHypothesisIds, "validationRecipe hypothesisId");
    if (hypothesisIds !== undefined && !hypothesisIds.has(record.hypothesisId)) {
      fail(`validationRecipe ${record.id} references unknown hypothesis: ${record.hypothesisId}`);
    }
    assertNonEmptyList(record.requiredFixtures, `validationRecipe ${record.id} requiredFixtures`);
    assertNonEmptyList(record.steps, `validationRecipe ${record.id} steps`);
    assertNonEmpty(record.expectedResult, `validationRecipe ${record.id} expectedResult`);
    assertNonEmptyList(record.safetyNotes, `validationRecipe ${record.id} safetyNotes`);
    assertNonEmptyList(
      record.materializationHints,
      `validationRecipe ${record.id} materializationHints`,
    );
    for (const knownGap of record.knownGaps) {
      assertNonEmpty(knownGap, `validationRecipe ${record.id} knownGap`);
    }
  }

  return sortValidationRecipes(records);
}

export function sortValidationRecipes(
  records: ReadonlyArray<ValidationRecipe>,
): ValidationRecipe[] {
  return [...records].sort(
    (a, b) => a.hypothesisId.localeCompare(b.hypothesisId) || a.id.localeCompare(b.id),
  );
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    fail(`${label} is required`);
  }
}

function assertNonEmptyList(values: ReadonlyArray<string>, label: string): void {
  if (values.length === 0) {
    fail(`${label} are required`);
  }
  for (const value of values) {
    assertNonEmpty(value, label);
  }
}

function assertUnique(value: string, seen: Set<string>, label: string): void {
  if (seen.has(value)) {
    fail(`${label} is duplicated: ${value}`);
  }
  seen.add(value);
}

function toSet(values: ReadonlySet<string> | ReadonlyArray<string>): Set<string> {
  return values instanceof Set ? new Set(values) : new Set(values);
}

function fail(message: string): never {
  throw new ValidationRecipeValidationError(message);
}
