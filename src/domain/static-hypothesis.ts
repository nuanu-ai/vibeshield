import { securityGraphStableId } from "./security-graph.js";

export interface StaticHypothesis {
  readonly id: string;
  readonly candidateId: string;
  readonly status: StaticHypothesisStatus;
  readonly staticConfidence: number;
  readonly title: string;
  readonly pathSummary: string;
  readonly supportingEvidenceIds: ReadonlyArray<string>;
  readonly contradictingEvidenceIds: ReadonlyArray<string>;
  readonly coverageState: StaticHypothesisCoverageState;
  readonly runtimeValidationRequired: boolean;
  /** Deterministic promotion decision. Only publishable records may become owner cards. */
  readonly promotion: StaticHypothesisPromotion;
}

export interface StaticHypothesisPromotion {
  readonly publishable: boolean;
  readonly source: "external_input" | "missing_or_untyped";
  readonly sink: "typed_security_sink" | "generic_or_untyped" | "missing";
  readonly path: "connected_security_flow" | "structural_only" | "missing";
  readonly control: "absent" | "effective" | "irrelevant" | "ambiguous";
  readonly evidence: "current_line_pinned" | "missing_or_stale";
  readonly rootCauseKey?: string;
  readonly reasons: ReadonlyArray<StaticHypothesisPromotionReason>;
}

export type StaticHypothesisPromotionReason =
  | "candidate_coverage_incomplete"
  | "connected_security_flow_observed"
  | "control_coverage_incomplete"
  | "current_line_pinned_evidence_observed"
  | "effective_control_dominates_sink"
  | "external_source_observed"
  | "generic_or_untyped_sink"
  | "matching_control_not_observed"
  | "missing_current_line_pinned_evidence"
  | "missing_external_source"
  | "missing_security_flow"
  | "security_flow_coverage_incomplete"
  | "structural_path_only"
  | "typed_security_sink_observed"
  | "control_effect_ambiguous";

export type StaticHypothesisStatus =
  | "candidate"
  | "statically_supported"
  | "statically_contradicted"
  | "inconclusive";

export type StaticHypothesisCoverageState =
  | "checked"
  | "skipped"
  | "failed"
  | "degraded"
  | "partial";

export interface StaticHypothesisValidationContext {
  readonly candidateIds?: ReadonlySet<string> | ReadonlyArray<string>;
}

const STATUSES = new Set<StaticHypothesisStatus>([
  "candidate",
  "statically_supported",
  "statically_contradicted",
  "inconclusive",
]);

const COVERAGE_STATES = new Set<StaticHypothesisCoverageState>([
  "checked",
  "skipped",
  "failed",
  "degraded",
  "partial",
]);

export class StaticHypothesisValidationError extends Error {
  override readonly name = "StaticHypothesisValidationError";
}

export function staticHypothesisId(graphVersion: string, candidateId: string): string {
  return securityGraphStableId("static_hypothesis", [graphVersion, candidateId]);
}

export function validateStaticHypothesisRecords(
  records: ReadonlyArray<StaticHypothesis>,
  context: StaticHypothesisValidationContext = {},
): StaticHypothesis[] {
  const candidateIds = context.candidateIds === undefined ? undefined : toSet(context.candidateIds);
  const seenIds = new Set<string>();
  const seenCandidateIds = new Set<string>();

  for (const record of records) {
    assertNonEmpty(record.id, "staticHypothesis id");
    assertUnique(record.id, seenIds, "staticHypothesis id");
    assertNonEmpty(record.candidateId, `staticHypothesis ${record.id} candidateId`);
    assertUnique(record.candidateId, seenCandidateIds, "staticHypothesis candidateId");
    if (candidateIds !== undefined && !candidateIds.has(record.candidateId)) {
      fail(`staticHypothesis ${record.id} references unknown candidate: ${record.candidateId}`);
    }
    assertKnown(record.status, STATUSES, `staticHypothesis ${record.id} status`);
    assertKnown(
      record.coverageState,
      COVERAGE_STATES,
      `staticHypothesis ${record.id} coverageState`,
    );
    assertConfidence(record.staticConfidence, `staticHypothesis ${record.id} staticConfidence`);
    assertNonEmpty(record.title, `staticHypothesis ${record.id} title`);
    assertNonEmpty(record.pathSummary, `staticHypothesis ${record.id} pathSummary`);

    if (record.status === "statically_supported" && record.supportingEvidenceIds.length === 0) {
      fail(`staticHypothesis ${record.id} statically_supported requires supporting evidence`);
    }
    if (record.status === "statically_supported" && !record.promotion.publishable) {
      fail(`staticHypothesis ${record.id} statically_supported must be publishable`);
    }
    if (record.status === "statically_supported" && record.promotion.rootCauseKey === undefined) {
      fail(`staticHypothesis ${record.id} statically_supported requires a rootCauseKey`);
    }
    if (record.status !== "statically_supported" && record.promotion.publishable) {
      fail(`staticHypothesis ${record.id} non-supported status cannot be publishable`);
    }
    if (
      record.status === "statically_contradicted" &&
      record.contradictingEvidenceIds.length === 0
    ) {
      fail(`staticHypothesis ${record.id} statically_contradicted requires contradicting evidence`);
    }
    for (const evidenceId of [
      ...record.supportingEvidenceIds,
      ...record.contradictingEvidenceIds,
    ]) {
      assertNonEmpty(evidenceId, `staticHypothesis ${record.id} evidenceId`);
    }
    if (record.promotion.reasons.length === 0) {
      fail(`staticHypothesis ${record.id} promotion reasons are required`);
    }
    if (record.promotion.rootCauseKey !== undefined) {
      assertNonEmpty(record.promotion.rootCauseKey, `staticHypothesis ${record.id} rootCauseKey`);
    }
  }

  return sortStaticHypotheses(records);
}

export function sortStaticHypotheses(records: ReadonlyArray<StaticHypothesis>): StaticHypothesis[] {
  return [...records].sort(
    (a, b) => a.candidateId.localeCompare(b.candidateId) || a.id.localeCompare(b.id),
  );
}

function assertKnown<T extends string>(value: string, known: ReadonlySet<T>, label: string): void {
  if (!known.has(value as T)) {
    fail(`${label} is invalid: ${value}`);
  }
}

function assertNonEmpty(value: string, label: string): void {
  if (value.trim() === "") {
    fail(`${label} is required`);
  }
}

function assertConfidence(value: number, label: string): void {
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    fail(`${label} must be between 0 and 1`);
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
  throw new StaticHypothesisValidationError(message);
}
