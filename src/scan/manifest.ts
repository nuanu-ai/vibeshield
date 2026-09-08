import type { Snapshot } from "./contracts.js";
import { LIMITS } from "./limits.js";

const ignored = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  "out",
  "target",
  "vendor",
  ".venv",
  "venv",
  "__pycache__",
  ".cache",
  "coverage",
  "logs",
]);
export function isSafeRepositoryPath(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 4096 &&
    // biome-ignore lint/suspicious/noControlCharactersInRegex: Reject control bytes in untrusted paths.
    !/[\\:\x00-\x1f\x7f]/.test(value) &&
    value
      .split("/")
      .every((part) => part !== "" && part !== "." && part !== ".." && !ignored.has(part))
  );
}
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
export function validateAcquisition(value: unknown): {
  snapshot: Snapshot;
  fetchedCommits: string[];
} {
  const fail = (): never => {
    throw new Error("Invalid snapshot");
  };
  if (
    !isRecord(value) ||
    !isRecord(value.snapshot) ||
    !Array.isArray(value.entries) ||
    !Array.isArray(value.fetchedCommits)
  )
    return fail();
  const s = value.snapshot;
  if (
    typeof s.url !== "string" ||
    typeof s.commit !== "string" ||
    !/^[a-f0-9]{40}$/.test(s.commit) ||
    !Array.isArray(s.files) ||
    !Array.isArray(s.languages) ||
    s.languages.some((x) => typeof x !== "string" || !/^[A-Za-z+# ]{1,30}$/.test(x)) ||
    !isRecord(s.history) ||
    typeof s.history.truncated !== "boolean" ||
    typeof s.oversized !== "number" ||
    !Number.isSafeInteger(s.oversized) ||
    s.oversized < 0 ||
    s.oversized > LIMITS.files ||
    value.fetchedCommits.length < 1 ||
    value.fetchedCommits.length > LIMITS.historyCommits ||
    value.fetchedCommits.some((x) => typeof x !== "string" || !/^[a-f0-9]{40}$/.test(x)) ||
    new Set(value.fetchedCommits).size !== value.fetchedCommits.length ||
    !value.fetchedCommits.includes(s.commit) ||
    s.history.commits !== value.fetchedCommits.length ||
    value.entries.length > LIMITS.files ||
    s.files.length !== value.entries.length
  )
    return fail();
  let bytes = 0;
  const files: string[] = [];
  for (const entry of value.entries) {
    if (
      !isRecord(entry) ||
      entry.kind !== "file" ||
      !isSafeRepositoryPath(entry.path) ||
      typeof entry.size !== "number" ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 0 ||
      entry.size > 5 * 1024 * 1024
    )
      return fail();
    files.push(entry.path);
    bytes += entry.size;
  }
  const declaredFiles = s.files;
  if (
    bytes > LIMITS.snapshotBytes ||
    new Set(files).size !== files.length ||
    files.some((file, i) => file !== declaredFiles[i])
  )
    return fail();
  return {
    snapshot: {
      url: s.url,
      commit: s.commit,
      files,
      languages: s.languages as string[],
      oversized: s.oversized,
      history: { commits: value.fetchedCommits.length, truncated: s.history.truncated },
    },
    fetchedCommits: value.fetchedCommits as string[],
  };
}
