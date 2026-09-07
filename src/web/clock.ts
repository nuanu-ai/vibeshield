import { LIMITS } from "../scan/limits.js";

export interface Clock {
  now(): number;
  schedule(delayMs: number, callback: () => void): () => void;
}
export const systemClock: Clock = {
  now: () => Date.now(),
  schedule: (delayMs, callback) => {
    const timer = setTimeout(callback, Math.min(2_147_483_647, Math.max(0, delayMs)));
    return () => clearTimeout(timer);
  },
};

export interface ScanDeadline {
  clock: Clock;
  signal: AbortSignal;
  remainingMs(): number;
  check(): void;
  abort(): void;
  dispose(): void;
}

// Internal bridge preserves ExecuteScan's AbortSignal-only boundary. The job
// owns registration; standalone executors own and dispose their own deadline.
const deadlines = new WeakMap<AbortSignal, ScanDeadline>();
export function deadlineFor(signal: AbortSignal): ScanDeadline | undefined {
  return deadlines.get(signal);
}
export function createScanDeadline(clock: Clock, parent?: AbortSignal): ScanDeadline {
  return createDeadline(clock, LIMITS.totalMs, parent);
}
export function createStageDeadline(parent: ScanDeadline): ScanDeadline {
  return createDeadline(
    parent.clock,
    Math.min(LIMITS.scannerMs, parent.remainingMs()),
    parent.signal,
  );
}
function createDeadline(clock: Clock, budgetMs: number, parent?: AbortSignal): ScanDeadline {
  const controller = new AbortController();
  const expiresAt = clock.now() + budgetMs;
  const abort = () => controller.abort(new Error("Scan interrupted or deadline exceeded"));
  const cancel = clock.schedule(budgetMs, abort);
  parent?.addEventListener("abort", abort, { once: true });
  if (parent?.aborted) abort();
  const deadline: ScanDeadline = {
    clock,
    signal: controller.signal,
    remainingMs: () => Math.max(0, expiresAt - clock.now()),
    check() {
      if (clock.now() >= expiresAt) abort();
      controller.signal.throwIfAborted();
    },
    abort,
    dispose() {
      cancel();
      parent?.removeEventListener("abort", abort);
      deadlines.delete(controller.signal);
    },
  };
  deadlines.set(controller.signal, deadline);
  return deadline;
}
