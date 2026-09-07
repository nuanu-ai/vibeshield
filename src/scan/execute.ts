import type { SandboxRuntime, SandboxSession } from "../ports/sandbox-runtime.js";
import {
  createScanDeadline,
  createStageDeadline,
  deadlineFor,
  type ScanDeadline,
  systemClock,
} from "../web/clock.js";
import { CleanupError, type ExecuteScan } from "../web/jobs.js";
import type { Progress, Provenance, Report, ScannerId, ScanResult, Stage } from "./contracts.js";
import { LIMITS } from "./limits.js";
import { defaultPolicy } from "./policy.js";
import { buildReport } from "./report.js";
import { scanGitleaks } from "./scanners/gitleaks.js";
import { scanOpengrep } from "./scanners/opengrep.js";
import { readOsvAdvisoryData, scanOsv } from "./scanners/osv.js";
import type { ScannerContext } from "./scanners/shared.js";
import { scanTrivy } from "./scanners/trivy.js";
import { scanZizmor } from "./scanners/zizmor.js";
import { acquire, parseRepositoryUrl } from "./source.js";

const scanners: readonly [ScannerId, (context: ScannerContext) => Promise<ScanResult>][] = [
  ["gitleaks", scanGitleaks],
  ["opengrep", scanOpengrep],
  ["osv", scanOsv],
  ["trivy", scanTrivy],
  ["zizmor", scanZizmor],
];

export function createExecutor(runtime: SandboxRuntime, provenance: Provenance): ExecuteScan {
  return async (request, signal, emit) => {
    const registered = deadlineFor(signal);
    const deadline = registered ?? createScanDeadline(systemClock, signal);
    const name = `vibeshield-web-${request.id}`;
    let created = false;
    let creationCleanupFailed = false;
    let cleanup: Promise<void> | undefined;
    let report: Report | undefined;
    let failure: Error | undefined;
    let stage: Stage = "prepare";
    const progress = (status: Progress["status"], message: string) =>
      emit({ stage, status, message });
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
        emit({ stage: waiting, status: "waiting", message: "Waiting." });
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
      const session = boundedSession(raw, deadline);
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
          progress(
            status,
            result.coverage.some(
              (entry) => entry.status === "failed" || entry.status === "degraded",
            )
              ? "Check completed with coverage limitations."
              : "Check finished; coverage details are in the report.",
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
                reason: deadline.signal.aborted
                  ? "Scan interrupted or overall deadline exceeded; this check did not complete."
                  : stageDeadline.signal.aborted
                    ? "Scanner exceeded its two-minute budget; this check did not complete."
                    : "Scanner failed; this check did not complete.",
              },
            ],
          });
          progress("failed", "Check did not complete.");
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
    } catch {
      progress("failed", "Scan could not prepare a repository report.");
      failure = new Error("Scan failed before a report could be prepared");
    } finally {
      stage = "cleanup";
      progress("running", "Removing temporary scan resources.");
      try {
        if (creationCleanupFailed) {
          progress("failed", "Temporary resource cleanup could not be verified.");
          failure = new CleanupError();
        } else {
          if (created) await remove();
          progress("completed", "Temporary scan resources removed.");
        }
      } catch {
        progress("failed", "Temporary resource cleanup could not be verified.");
        failure = new CleanupError(report);
      } finally {
        deadline.signal.removeEventListener("abort", abort);
        if (!registered) deadline.dispose();
      }
    }
    if (failure) throw failure;
    if (!report) throw new Error("Scan failed before a report could be prepared");
    return report;
  };
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
function boundedSession(session: SandboxSession, deadline: ScanDeadline): SandboxSession {
  const io = <T>(operation: () => Promise<T>) =>
    bounded(async () => {
      try {
        return await operation();
      } catch (error) {
        // Nonzero scanner exits are ordinary results. A rejected SDK operation
        // means the sandbox transport is unusable; stop issuing further commands.
        deadline.abort();
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
