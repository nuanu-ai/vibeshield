import type { SandboxRuntime, SandboxSession } from "../ports/sandbox-runtime.js";
import {
  createScanDeadline,
  createStageDeadline,
  deadlineFor,
  type ScanDeadline,
  systemClock,
} from "../web/clock.js";
import { CleanupError, type ExecuteScan } from "../web/jobs.js";
import type {
  FailureCode,
  Progress,
  Provenance,
  Report,
  ScannerId,
  ScanResult,
  Stage,
} from "./contracts.js";
import { ScanFailure } from "./contracts.js";
import { LIMITS } from "./limits.js";
import { defaultPolicy } from "./policy.js";
import { buildReport } from "./report.js";
import { scanGitleaks } from "./scanners/gitleaks.js";
import { scanOpengrep } from "./scanners/opengrep.js";
import { readOsvAdvisoryData, scanOsv } from "./scanners/osv.js";
import type { ScannerContext } from "./scanners/shared.js";
import { scanTrivy } from "./scanners/trivy.js";
import { scanZizmor } from "./scanners/zizmor.js";
import { AcquisitionError, acquire, parseRepositoryUrl } from "./source.js";

const scanners: readonly [ScannerId, (context: ScannerContext) => Promise<ScanResult>][] = [
  ["gitleaks", scanGitleaks],
  ["opengrep", scanOpengrep],
  ["osv", scanOsv],
  ["trivy", scanTrivy],
  ["zizmor", scanZizmor],
];

export type ScanDiagnostic =
  | {
      readonly event: "scan_stage";
      readonly scanId: string;
      readonly stage: Stage;
      readonly status: Progress["status"];
      readonly reason?: string;
    }
  | {
      readonly event: "scan_finished";
      readonly scanId: string;
      readonly status: "completed" | "failed" | "cleanup_failed";
    };

export function createExecutor(
  runtime: SandboxRuntime,
  provenance: Provenance,
  diagnostic?: (event: ScanDiagnostic) => void,
  emitFinished = true,
): ExecuteScan {
  return async (request, signal, emit) => {
    const registered = deadlineFor(signal);
    const deadline = registered ?? createScanDeadline(systemClock, signal);
    const name = `vibeshield-web-${request.id}`;
    let created = false;
    let creationCleanupFailed = false;
    let cleanup: Promise<void> | undefined;
    let report: Report | undefined;
    let failure: Error | undefined;
    let failureCode: FailureCode = "internal";
    let stage: Stage = "prepare";
    let transportFailed = false;
    const observe = (event: ScanDiagnostic) => {
      try {
        diagnostic?.(event);
      } catch {
        // Operator logging must not change scan behavior.
      }
    };
    const progress = (status: Progress["status"], message: string, reason?: string) => {
      emit({ stage, status, message });
      if (status !== "waiting")
        observe({
          event: "scan_stage",
          scanId: request.id,
          stage,
          status,
          ...(reason === undefined ? {} : { reason }),
        });
    };
    const overallFailureReason = () =>
      deadline.remainingMs() === 0
        ? "overall_timeout"
        : transportFailed
          ? "sandbox_failed"
          : deadline.signal.aborted
            ? "cancelled"
            : undefined;
    const remove = () => {
      cleanup ??= runtime.destroy(name);
      return cleanup;
    };
    const abort = () => {
      if (created) void remove().catch(() => {});
    };
    deadline.signal.addEventListener("abort", abort, { once: true });
    try {
      for (const waiting of [
        "prepare",
        "acquire",
        ...scanners.map(([id]) => id),
        "report",
        "cleanup",
      ] as const)
        emit({ stage: waiting, status: "waiting", message: "" });
      progress("running", "Preparing scan environment.");
      const url = parseRepositoryUrl(request.url);
      if (!(await bounded(() => runtime.isAvailable(), deadline)).available) throw new Error();
      deadline.check();
      // Creation must settle even after abort: a late-created VM must be removed
      // before execute can settle. The runtime owns cancellation during creation.
      let raw: SandboxSession;
      try {
        raw = await runtime.create({ name, imageTag: provenance.image, signal: deadline.signal });
        created = true;
      } catch (error) {
        // The runtime owns cleanup on failed creation; an AggregateError
        // means it could not verify that cleanup. Never delete an unowned name.
        creationCleanupFailed = error instanceof AggregateError;
        throw error;
      }
      deadline.check();
      const session = boundedSession(raw, deadline, () => {
        transportFailed = true;
      });
      progress("completed", "Scan environment prepared.");
      stage = "acquire";
      progress("running", "Fetching repository snapshot.");
      const repository = await acquire(session, url, deadline.signal);
      deadline.check();
      progress("completed", "Repository snapshot acquired.");
      const results: ScanResult[] = [];
      const scanProvenance = structuredClone(provenance);
      for (const [id, scan] of scanners) {
        stage = id;
        const stageDeadline = createStageDeadline(deadline);
        const stageSession = scannerSession(session, stageDeadline, deadline);
        try {
          deadline.check();
          stageDeadline.check();
          progress("running", `Running ${id}.`);
          const result = await scan({
            session: stageSession,
            snapshot: repository,
            signal: stageDeadline.signal,
          });
          deadline.check();
          stageDeadline.check();
          results.push(result);
          if (id === "osv") {
            const advisory = await readOsvAdvisoryData(stageSession);
            deadline.check();
            stageDeadline.check();
            if (advisory && new Date(advisory.retrievedAt).toISOString() === advisory.retrievedAt)
              scanProvenance.advisoryData.push(advisory);
          }
          const status = result.coverage.some((entry) => entry.status === "failed")
            ? "failed"
            : result.coverage.every((entry) => entry.status === "skipped")
              ? "skipped"
              : "completed";
          const found = result.findings.length;
          const limited = result.coverage.some(
            (entry) => entry.status === "failed" || entry.status === "degraded",
          );
          progress(
            status,
            status === "skipped"
              ? "Nothing here for this check to look at."
              : found === 0
                ? `Found nothing${limited ? ", and part of it could not be checked" : ""}.`
                : `Found ${found} thing${found === 1 ? "" : "s"} to look at${limited ? ", and part of it could not be checked" : ""}.`,
            status === "failed" ? "scanner_failed" : undefined,
          );
        } catch {
          results.push({
            findings: [],
            coverage: [
              {
                scanner: id,
                area: "engine",
                status: "failed",
                applicable: true,
                reason: overallFailureReason()
                  ? "Scan interrupted or overall deadline exceeded; this check did not complete."
                  : stageDeadline.remainingMs() === 0
                    ? "Scanner exceeded its two-minute budget; this check did not complete."
                    : "Scanner failed; this check did not complete.",
              },
            ],
          });
          progress(
            "failed",
            "This check could not finish.",
            overallFailureReason() ??
              (stageDeadline.remainingMs() === 0
                ? "timeout"
                : stageDeadline.signal.aborted
                  ? "cancelled"
                  : "scanner_failed"),
          );
        } finally {
          stageDeadline.dispose();
        }
      }
      stage = "report";
      progress("running", "Preparing the report.");
      report = buildReport({
        repository,
        provenance: scanProvenance,
        generatedAt: new Date(deadline.clock.now()).toISOString(),
        results,
        policy: defaultPolicy,
      });
      progress("completed", "Report prepared.");
    } catch (error) {
      const reason =
        overallFailureReason() ??
        (error instanceof AcquisitionError
          ? error.code
          : stage === "prepare"
            ? "prepare_failed"
            : stage === "report"
              ? "report_failed"
              : "internal_error");
      progress("failed", "Scan could not prepare a repository report.", reason);
      failureCode = failureCodeFor(reason);
      failure = new ScanFailure(failureCode);
    } finally {
      stage = "cleanup";
      progress("running", "Removing temporary scan resources.");
      try {
        if (creationCleanupFailed) {
          progress("failed", "Temporary resource cleanup could not be verified.", "cleanup_failed");
          failure = new CleanupError(undefined, failureCode);
        } else {
          if (created) await remove();
          progress("completed", "Temporary scan resources removed.");
        }
      } catch {
        progress("failed", "Temporary resource cleanup could not be verified.", "cleanup_failed");
        failure = new CleanupError(report, failureCode);
      } finally {
        deadline.signal.removeEventListener("abort", abort);
        if (!registered) deadline.dispose();
      }
    }
    if (failure) {
      if (emitFinished)
        observe({
          event: "scan_finished",
          scanId: request.id,
          status: failure instanceof CleanupError ? "cleanup_failed" : "failed",
        });
      throw failure;
    }
    if (!report) {
      if (emitFinished) observe({ event: "scan_finished", scanId: request.id, status: "failed" });
      throw new ScanFailure(failureCode);
    }
    if (emitFinished) observe({ event: "scan_finished", scanId: request.id, status: "completed" });
    return report;
  };
}

function failureCodeFor(reason: string): FailureCode {
  switch (reason) {
    case "git_failed":
    case "invalid_snapshot":
      return "repository_unreachable";
    case "file_limit":
    case "snapshot_limit":
      return "repository_too_large";
    case "timeout":
    case "overall_timeout":
      return "took_too_long";
    case "sandbox_failed":
    case "prepare_failed":
      return "environment_unavailable";
    default:
      return "internal";
  }
}

/** One stage budget includes every subcommand and export operation. Runtime
 * cancellation remains attached to the overall signal: aborting that signal
 * destroys the VM. The existing guest wrapper stops each command at the remaining
 * stage budget; await its settlement before another scanner uses the sandbox. */
function scannerSession(
  session: SandboxSession,
  stage: ScanDeadline,
  overall: ScanDeadline,
): SandboxSession {
  const io = async <T>(operation: () => Promise<T>): Promise<T> => {
    overall.check();
    stage.check();
    const result = await operation();
    overall.check();
    stage.check();
    return result;
  };
  return {
    id: session.id,
    exec: (command, options) =>
      io(() =>
        session.exec(command, {
          ...options,
          signal: overall.signal,
          timeoutMs: Math.min(options?.timeoutMs ?? LIMITS.scannerMs, stage.remainingMs()),
        }),
      ),
    read: (path) => io(() => session.read(path)),
    download: (path) => io(() => session.download(path)),
    upload: (local, guest) => io(() => session.upload(local, guest)),
    uploadBytes: (path, data) => io(() => session.uploadBytes(path, data)),
    destroy: () => session.destroy(),
  };
}

/** Check wall time at every I/O boundary, including exports whose API has no signal. */
async function bounded<T>(operation: () => Promise<T>, deadline: ScanDeadline): Promise<T> {
  deadline.check();
  let abort!: () => void;
  const cancelled = new Promise<never>((_resolve, reject) => {
    abort = () => reject(new Error("Scan interrupted"));
    deadline.signal.addEventListener("abort", abort, { once: true });
  });
  try {
    const result = await Promise.race([operation(), cancelled]);
    deadline.check();
    return result;
  } finally {
    deadline.signal.removeEventListener("abort", abort);
  }
}
function boundedSession(
  session: SandboxSession,
  deadline: ScanDeadline,
  transportFailed: () => void,
): SandboxSession {
  const io = <T>(operation: () => Promise<T>) =>
    bounded(async () => {
      try {
        return await operation();
      } catch (error) {
        // Nonzero scanner exits are ordinary results. A rejected SDK operation
        // means the sandbox transport is unusable; stop issuing further commands.
        if (!deadline.signal.aborted) {
          transportFailed();
          deadline.abort();
        }
        throw error;
      }
    }, deadline);
  return {
    id: session.id,
    exec: (command, options) =>
      io(() => session.exec(command, { ...options, signal: deadline.signal })),
    read: (path) => io(() => session.read(path)),
    download: (path) => io(() => session.download(path)),
    upload: (local, guest) => io(() => session.upload(local, guest)),
    uploadBytes: (path, data) => io(() => session.uploadBytes(path, data)),
    destroy: () => session.destroy(),
  };
}
