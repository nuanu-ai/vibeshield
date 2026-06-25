/**
 * Run identity and lifecycle.
 *
 * A Run is one invocation of `vibeshield scan`. It has a stable id, a source
 * reference, and an ordered list of stage attempts. The run is the unit of
 * resume: state is rebuilt from persisted attempts, never from files on disk.
 */

/** Stable, unique id for a scan run (e.g. an ISO timestamp + short nonce). */
export type RunId = string;

/** Stage id within a run. Matches a registered StageDefinition id. */
export type StageId = string;

export type RunStatus = "failed" | "running" | "success";

/** A single attempt of one stage within a run. */
export interface StageAttempt {
  /** Monotonic attempt number for this (run, stage). 1-based. */
  readonly attempt: number;
  readonly stageId: StageId;
  readonly stageVersion: string;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly status: StageAttemptStatus;
  /** Human-readable error message when status is "failed". */
  readonly error?: string;
  /** Blob refs for output artifacts produced by this attempt. */
  readonly outputs: ReadonlyArray<ArtifactRef>;
  /** Arbitrary JSON persisted alongside the attempt; handed back as input to downstream stages. */
  readonly data?: Readonly<Record<string, unknown>>;
  /** Stage ids that this attempt invalidated (became stale) when it ran. */
  readonly markedStale?: ReadonlyArray<StageId>;
}

export type StageAttemptStatus = "failed" | "running" | "stale" | "success";

/**
 * A Run is the aggregate root for scan state. Built from the state store; the
 * domain never reads run files off disk to rebuild it.
 */
export interface Run {
  readonly id: RunId;
  readonly source: SourceInput;
  readonly createdAt: string;
  readonly finishedAt?: string;
  readonly status: RunStatus;
  /** Latest attempt per stage id, in registration order. */
  readonly attempts: ReadonlyMap<StageId, StageAttempt>;
  /** Stages that are stale (a dependency was rerun after them) and need rerun. */
  readonly staleStages: ReadonlySet<StageId>;
}

/** What the owner pointed VibeShield at. */
export type SourceInput = GithubSource | LocalSource;

export interface GithubSource {
  readonly kind: "github";
  readonly url: string;
}

export interface LocalSource {
  readonly kind: "local";
  /** Absolute host path that was scanned. */
  readonly path: string;
  /** Git origin remote URL when the local worktree has one. */
  readonly originUrl?: string;
}

/** Reference to a stored artifact blob (content-addressed by sha256). */
export interface ArtifactRef {
  readonly blobSha256: string;
  /** Logical role this artifact plays (e.g. "manifest", "secrets.raw"). */
  readonly role: ArtifactRole;
  /** Byte size of the stored blob. */
  readonly bytes: number;
}

export type ArtifactRole =
  | "manifest"
  | "inventory"
  | "scanner.raw"
  | "program-analysis.raw"
  | "program-analysis.slice"
  | "repository-map.json"
  | "report.json"
  | "report.md"
  | "report.html";
