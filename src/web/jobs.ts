import { randomUUID } from "node:crypto";
import type { Progress, Report } from "../scan/contracts.js";
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
  error?: string;
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
    super("Another scan is running or cleanup is pending");
  }
}
export class CleanupError extends Error {
  constructor(readonly report?: Report) {
    super("Sandbox cleanup could not be verified; operator cleanup is required");
  }
}
export function createJobs(options: {
  execute: ExecuteScan;
  cleanup: () => Promise<void>;
  clock: Clock;
}): JobStore {
  const jobs = new Map<string, Job>();
  const expiry = new Map<string, () => void>();
  type Active = { job: Job; deadline: ScanDeadline; done: Promise<void>; report?: Report };
  let active: Active | undefined;
  let stopped = false;
  let retry: Promise<void> | undefined;
  let stopping: Promise<void> | undefined;
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
      delete job.error;
    } else {
      job.status = "failed";
      job.error =
        "Scan failed before a report could be prepared. Check repository access and the scanner environment.";
    }
    job.finishedAt = options.clock.now();
    if (active === current) active = undefined;
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
        } catch (error) {
          if (error instanceof CleanupError) {
            if (error.report) current.report = error.report;
            job.status = "cleanup-failed";
            job.error = error.message;
          } else finish(current);
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
        try {
          await options.cleanup();
        } catch {
          throw new CleanupError();
        }
        const cleanup = current.job.stages.find((stage) => stage.stage === "cleanup");
        if (cleanup) {
          cleanup.status = "completed";
          cleanup.message = "Temporary scan resources removed.";
        }
        finish(current);
      })();
      try {
        await retry;
      } finally {
        retry = undefined;
      }
    },
    async shutdown() {
      stopped = true;
      for (const cancel of expiry.values()) cancel();
      expiry.clear();
      active?.deadline.abort();
      if (stopping) return stopping;
      stopping = (async () => {
        await active?.done;
        await retry;
        if (active?.job.status === "cleanup-failed") throw new CleanupError();
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
