import { randomUUID } from "node:crypto";
import type { FailureCode, Progress, Report } from "../scan/contracts.js";
import { ScanFailure } from "../scan/contracts.js";
import type { ScanDiagnostic } from "../scan/execute.js";
import { LIMITS } from "../scan/limits.js";
import { parseRepositoryUrl } from "../scan/source.js";
import { type Clock, createScanDeadline, type ScanDeadline } from "./clock.js";
export type ExecuteScan = (
  request: { id: string; url: string },
  signal: AbortSignal,
  emit: (event: Progress) => void,
) => Promise<Report>;
export interface Job {
  id: string;
  url: string;
  createdAt: number;
  finishedAt?: number;
  status: "running" | "completed" | "failed" | "cleanup-failed";
  stages: Progress[];
  report?: Report;
  failure?: FailureCode;
}
export interface JobStore {
  start(url: string): { id: string };
  get(id: string): Job | undefined;
  busy(): boolean;
  shutdown(): Promise<void>;
  retryCleanup(): Promise<void>;
}
export class BusyError extends Error {
  constructor() {
    super("Another scan is still finishing. Try again in a few seconds.");
  }
}
export class CleanupError extends Error {
  constructor(
    readonly report?: Report,
    readonly code: FailureCode = "internal",
  ) {
    super("Sandbox cleanup could not be verified; operator cleanup is required");
  }
}
export function createJobs(options: {
  execute: ExecuteScan;
  cleanup: () => Promise<void>;
  clock: Clock;
  diagnostic?: (message: string) => void;
  lifecycle?: (event: ScanDiagnostic) => void;
}): JobStore {
  const jobs = new Map<string, Job>();
  const expiry = new Map<string, () => void>();
  type Active = {
    job: Job;
    deadline: ScanDeadline;
    done: Promise<void>;
    report?: Report;
    failure?: FailureCode;
    finishedStatus?: "completed" | "failed" | "cleanup_failed";
  };
  let active: Active | undefined;
  let stopped = false;
  let retry: Promise<void> | undefined;
  let stopping: Promise<void> | undefined;
  let cancelMaintenance: (() => void) | undefined;
  const lifecycle = (event: ScanDiagnostic) => {
    try {
      options.lifecycle?.(event);
    } catch {
      // Operator logging must not change job state.
    }
  };
  const publishFinished = (current: Active, status: "completed" | "failed" | "cleanup_failed") => {
    if (current.finishedStatus === status) return;
    current.finishedStatus = status;
    lifecycle({ event: "scan_finished", scanId: current.job.id, status });
  };
  const scheduleCleanup = (current: Active, attempt = 1) => {
    if (stopped || active !== current) return;
    cancelMaintenance = options.clock.schedule(5000, () => {
      cancelMaintenance = undefined;
      void store.retryCleanup().catch(() => {
        options.diagnostic?.(
          attempt < 3
            ? "Temporary resource cleanup retry failed. Admission remains closed."
            : "Temporary resource cleanup retries exhausted. Operator reconciliation is required.",
        );
        if (attempt < 3) scheduleCleanup(current, attempt + 1);
      });
    });
  };
  const remove = (id: string) => {
    expiry.get(id)?.();
    expiry.delete(id);
    jobs.delete(id);
  };
  const prune = () => {
    for (const job of jobs.values()) {
      if (
        job.finishedAt !== undefined &&
        options.clock.now() >= job.finishedAt + LIMITS.reportTtlMs
      )
        remove(job.id);
    }
    const completed = [...jobs.values()]
      .filter((job) => job.status === "completed")
      .sort((a, b) => (a.finishedAt ?? 0) - (b.finishedAt ?? 0));
    for (const job of completed.slice(0, Math.max(0, completed.length - LIMITS.reports)))
      remove(job.id);
  };
  const finish = (current: Active) => {
    const job = current.job;
    if (current.report) {
      job.report = current.report;
      job.status = "completed";
      delete job.failure;
    } else {
      job.status = "failed";
      job.failure = current.failure ?? "internal";
    }
    job.finishedAt = options.clock.now();
    if (active === current) {
      active = undefined;
      cancelMaintenance?.();
      cancelMaintenance = undefined;
    }
    if (!stopped)
      expiry.set(
        job.id,
        options.clock.schedule(LIMITS.reportTtlMs, () => remove(job.id)),
      );
    prune();
  };
  const store: JobStore = {
    start(value) {
      if (active || stopped) throw new BusyError();
      const url = parseRepositoryUrl(value);
      prune();
      const job: Job = {
        id: randomUUID(),
        url,
        createdAt: options.clock.now(),
        status: "running",
        stages: [],
      };
      const current: Active = {
        job,
        deadline: createScanDeadline(options.clock),
        done: Promise.resolve(),
      };
      active = current;
      jobs.set(job.id, job);
      current.done = (async () => {
        try {
          current.report = await options.execute(
            { id: job.id, url },
            current.deadline.signal,
            (event) => {
              if (job.status !== "running") return;
              const index = job.stages.findIndex((stage) => stage.stage === event.stage);
              if (index < 0) job.stages.push({ ...event });
              else job.stages[index] = { ...event };
            },
          );
          finish(current);
          publishFinished(current, "completed");
        } catch (error) {
          if (error instanceof CleanupError) {
            if (error.report) {
              current.report = error.report;
              job.report = error.report;
            }
            current.failure = error.code;
            job.status = "cleanup-failed";
            job.failure = "cleanup_pending";
            options.diagnostic?.(
              "Temporary resource cleanup could not be verified. Admission remains closed during bounded retries.",
            );
            scheduleCleanup(current);
          } else {
            current.failure = error instanceof ScanFailure ? error.code : "internal";
            finish(current);
            publishFinished(current, "failed");
          }
        } finally {
          current.deadline.dispose();
        }
      })();
      return { id: job.id };
    },
    get(id) {
      prune();
      const job = jobs.get(id);
      return job && structuredClone(job);
    },
    busy: () => active !== undefined || stopped,
    async retryCleanup() {
      if (retry) return retry;
      const current = active;
      if (current?.job.status !== "cleanup-failed") return;
      retry = (async () => {
        lifecycle({
          event: "scan_stage",
          scanId: current.job.id,
          stage: "cleanup",
          status: "running",
        });
        try {
          await options.cleanup();
        } catch {
          lifecycle({
            event: "scan_stage",
            scanId: current.job.id,
            stage: "cleanup",
            status: "failed",
            reason: "cleanup_failed",
          });
          throw new CleanupError();
        }
        const cleanup = current.job.stages.find((stage) => stage.stage === "cleanup");
        if (cleanup) {
          cleanup.status = "completed";
          cleanup.message = "Temporary scan resources removed.";
        }
        lifecycle({
          event: "scan_stage",
          scanId: current.job.id,
          stage: "cleanup",
          status: "completed",
        });
        finish(current);
        publishFinished(current, current.report ? "completed" : "failed");
      })();
      try {
        await retry;
      } finally {
        retry = undefined;
      }
    },
    async shutdown() {
      stopped = true;
      cancelMaintenance?.();
      cancelMaintenance = undefined;
      for (const cancel of expiry.values()) cancel();
      expiry.clear();
      active?.deadline.abort();
      if (stopping) return stopping;
      stopping = (async () => {
        await active?.done;
        await retry;
        if (active?.job.status === "cleanup-failed") {
          publishFinished(active, "cleanup_failed");
          throw new CleanupError();
        }
        try {
          await options.cleanup();
        } catch {
          throw new CleanupError();
        }
      })();
      try {
        await stopping;
      } finally {
        stopping = undefined;
      }
    },
  };
  return store;
}
