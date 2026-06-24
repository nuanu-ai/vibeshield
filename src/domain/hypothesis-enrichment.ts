import { securityGraphStableId } from "./security-graph.js";

export interface HypothesisEnrichment {
  readonly id: string;
  readonly hypothesisId: string;
  readonly source: HypothesisEnrichmentSource;
  readonly attackDescription: string;
  readonly assumptions: ReadonlyArray<string>;
  readonly impact: string;
  readonly remediation: string;
  readonly agentPrompt: string;
  readonly acceptanceCriteria: ReadonlyArray<string>;
  readonly validationRecipeText: string;
}

export type HypothesisEnrichmentSource = "catalog" | "model";

export interface HypothesisEnrichmentValidationContext {
  readonly hypothesisIds?: ReadonlySet<string> | ReadonlyArray<string>;
}

const SOURCES = new Set<HypothesisEnrichmentSource>(["catalog", "model"]);

export class HypothesisEnrichmentValidationError extends Error {
  override readonly name = "HypothesisEnrichmentValidationError";
}

export function hypothesisEnrichmentId(hypothesisId: string): string {
  return securityGraphStableId("hypothesis_enrichment", [hypothesisId]);
}

export function validateHypothesisEnrichments(
  records: ReadonlyArray<HypothesisEnrichment>,
  context: HypothesisEnrichmentValidationContext = {},
): HypothesisEnrichment[] {
  const hypothesisIds =
    context.hypothesisIds === undefined ? undefined : toSet(context.hypothesisIds);
  const seenIds = new Set<string>();
  const seenHypothesisIds = new Set<string>();

  for (const record of records) {
    assertNonEmpty(record.id, "hypothesisEnrichment id");
    assertUnique(record.id, seenIds, "hypothesisEnrichment id");
    assertNonEmpty(record.hypothesisId, `hypothesisEnrichment ${record.id} hypothesisId`);
    assertUnique(record.hypothesisId, seenHypothesisIds, "hypothesisEnrichment hypothesisId");
    if (hypothesisIds !== undefined && !hypothesisIds.has(record.hypothesisId)) {
      fail(
        `hypothesisEnrichment ${record.id} references unknown hypothesis: ${record.hypothesisId}`,
      );
    }
    if (!SOURCES.has(record.source)) {
      fail(`hypothesisEnrichment ${record.id} source is invalid: ${record.source}`);
    }
    assertNonEmpty(record.attackDescription, `hypothesisEnrichment ${record.id} attackDescription`);
    assertNonEmptyList(record.assumptions, `hypothesisEnrichment ${record.id} assumptions`);
    assertNonEmpty(record.impact, `hypothesisEnrichment ${record.id} impact`);
    assertNonEmpty(record.remediation, `hypothesisEnrichment ${record.id} remediation`);
    assertNonEmpty(record.agentPrompt, `hypothesisEnrichment ${record.id} agentPrompt`);
    assertNonEmptyList(
      record.acceptanceCriteria,
      `hypothesisEnrichment ${record.id} acceptanceCriteria`,
    );
    assertNonEmpty(
      record.validationRecipeText,
      `hypothesisEnrichment ${record.id} validationRecipeText`,
    );
  }

  return sortHypothesisEnrichments(records);
}

export function sortHypothesisEnrichments(
  records: ReadonlyArray<HypothesisEnrichment>,
): HypothesisEnrichment[] {
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
  throw new HypothesisEnrichmentValidationError(message);
}
