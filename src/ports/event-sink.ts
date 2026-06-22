/**
 * EventSink port — progress and lifecycle events for the renderer.
 *
 * One call per stage start/finish, scanner output, or error. The terminal
 * renderer subscribes here; nothing else observes progress.
 */

import type { StageId } from "../domain/run.js";

export type EventType =
  | "run-started"
  | "run-finished"
  | "stage-started"
  | "stage-finished"
  | "stage-failed"
  | "scan-progress"
  | "error";

export interface ScanEvent {
  readonly type: EventType;
  readonly stageId?: StageId;
  readonly message: string;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly timestamp: string;
}

export interface EventSink {
  emit(event: ScanEvent): void;
}
