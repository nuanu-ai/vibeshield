import type { VerdictImpact } from "./action.js";
import { securityGraphStableId } from "./security-graph.js";

export interface DeepActionGroup {
  readonly id: string;
  readonly leadKind: DeepActionGroupLeadKind;
  readonly remediationKey: string;
  readonly priorityScore: number;
  readonly verdictImpact: VerdictImpact;
  readonly directActionIds: ReadonlyArray<string>;
  readonly findingIds: ReadonlyArray<string>;
  readonly hypothesisIds: ReadonlyArray<string>;
  readonly evidenceIds: ReadonlyArray<string>;
  readonly affectedFiles: ReadonlyArray<string>;
  readonly reason: string;
}

export type DeepActionGroupLeadKind = "direct_finding" | "hypothesis";

export interface DeepActionGroupValidationContext {
  readonly directActionIds?: ReadonlySet<string> | ReadonlyArray<string>;
  readonly findingIds?: ReadonlySet<string> | ReadonlyArray<string>;
  readonly evidenceIds?: ReadonlySet<string> | ReadonlyArray<string>;
  readonly hypothesisIds?: ReadonlySet<string> | ReadonlyArray<string>;
}

const LEAD_KINDS = new Set<DeepActionGroupLeadKind>(["direct_finding", "hypothesis"]);
const VERDICT_IMPACTS = new Set<VerdictImpact>(["blocks-deploy", "degrades", "informational"]);

export class DeepActionGroupValidationError extends Error {
  override readonly name = "DeepActionGroupValidationError";
}

export function deepActionGroupId(parts: ReadonlyArray<string>): string {
  return securityGraphStableId("deep_action_group", parts);
}

export function validateDeepActionGroups(
  records: ReadonlyArray<DeepActionGroup>,
  context: DeepActionGroupValidationContext = {},
): DeepActionGroup[] {
  const directActionIds =
    context.directActionIds === undefined ? undefined : toSet(context.directActionIds);
  const findingIds = context.findingIds === undefined ? undefined : toSet(context.findingIds);
  const evidenceIds = context.evidenceIds === undefined ? undefined : toSet(context.evidenceIds);
  const hypothesisIds =
    context.hypothesisIds === undefined ? undefined : toSet(context.hypothesisIds);
  const seenIds = new Set<string>();

  for (const record of records) {
    assertNonEmpty(record.id, "deepActionGroup id");
    assertUnique(record.id, seenIds, "deepActionGroup id");
    assertKnown(record.leadKind, LEAD_KINDS, `deepActionGroup ${record.id} leadKind`);
    assertKnown(
      record.verdictImpact,
      VERDICT_IMPACTS,
      `deepActionGroup ${record.id} verdictImpact`,
    );
    assertNonEmpty(record.remediationKey, `deepActionGroup ${record.id} remediationKey`);
    assertPriority(record.priorityScore, `deepActionGroup ${record.id} priorityScore`);
    assertNonEmpty(record.reason, `deepActionGroup ${record.id} reason`);

    if (record.leadKind === "direct_finding" && record.directActionIds.length === 0) {
      fail(`deepActionGroup ${record.id} direct_finding lead requires directActionIds`);
    }
    if (record.leadKind === "hypothesis" && record.directActionIds.length > 0) {
      fail(`deepActionGroup ${record.id} hypothesis lead cannot carry directActionIds`);
    }
    if (record.leadKind === "hypothesis" && record.hypothesisIds.length === 0) {
      fail(`deepActionGroup ${record.id} hypothesis lead requires hypothesisIds`);
    }

    for (const directActionId of record.directActionIds) {
      assertNonEmpty(directActionId, `deepActionGroup ${record.id} directActionId`);
      if (directActionIds !== undefined && !directActionIds.has(directActionId)) {
        fail(`deepActionGroup ${record.id} references unknown direct action: ${directActionId}`);
      }
    }
    for (const findingId of record.findingIds) {
      assertNonEmpty(findingId, `deepActionGroup ${record.id} findingId`);
      if (findingIds !== undefined && !findingIds.has(findingId)) {
        fail(`deepActionGroup ${record.id} references unknown finding: ${findingId}`);
      }
    }
    for (const evidenceId of record.evidenceIds) {
      assertNonEmpty(evidenceId, `deepActionGroup ${record.id} evidenceId`);
      if (evidenceIds !== undefined && !evidenceIds.has(evidenceId)) {
        fail(`deepActionGroup ${record.id} references unknown evidence: ${evidenceId}`);
      }
    }
    for (const hypothesisId of record.hypothesisIds) {
      assertNonEmpty(hypothesisId, `deepActionGroup ${record.id} hypothesisId`);
      if (hypothesisIds !== undefined && !hypothesisIds.has(hypothesisId)) {
        fail(`deepActionGroup ${record.id} references unknown hypothesis: ${hypothesisId}`);
      }
    }
    for (const affectedFile of record.affectedFiles) {
      assertNonEmpty(affectedFile, `deepActionGroup ${record.id} affectedFile`);
    }
  }

  return sortDeepActionGroups(records);
}

export function sortDeepActionGroups(records: ReadonlyArray<DeepActionGroup>): DeepActionGroup[] {
  return [...records].sort(
    (a, b) =>
      b.priorityScore - a.priorityScore ||
      leadRank(b.leadKind) - leadRank(a.leadKind) ||
      a.remediationKey.localeCompare(b.remediationKey) ||
      a.id.localeCompare(b.id),
  );
}

function leadRank(leadKind: DeepActionGroupLeadKind): number {
  return leadKind === "direct_finding" ? 1 : 0;
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

function assertPriority(value: number, label: string): void {
  if (!Number.isFinite(value) || value < 0) {
    fail(`${label} must be a non-negative finite number`);
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
  throw new DeepActionGroupValidationError(message);
}
