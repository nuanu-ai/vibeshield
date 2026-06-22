/**
 * Verdict — rule-computed, before any model call.
 *
 * No absolute "safe" wording. `looks-ok-for-now` requires the applicable
 * required checks to have completed; failed/missing/stale required coverage
 * yields `scan-incomplete`.
 */
export type Verdict =
  | "critical-fix-needed"
  | "not-ready-to-deploy"
  | "looks-ok-for-now"
  | "scan-incomplete";

export const VERDICT_ORDER: ReadonlyArray<Verdict> = [
  "critical-fix-needed",
  "not-ready-to-deploy",
  "scan-incomplete",
  "looks-ok-for-now",
];

/** Human-facing label for a verdict. */
export function verdictLabel(v: Verdict): string {
  switch (v) {
    case "critical-fix-needed":
      return "Critical fix needed";
    case "not-ready-to-deploy":
      return "Not ready to deploy";
    case "scan-incomplete":
      return "Scan incomplete";
    case "looks-ok-for-now":
      return "Looks OK for now";
  }
}
