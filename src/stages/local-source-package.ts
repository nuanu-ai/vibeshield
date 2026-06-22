import { execFile } from "node:child_process";
import { copyFile, lstat, mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { ManifestExclusion } from "../domain/manifest.js";

const execFileP = promisify(execFile);

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_FILES = 50_000;
const MAX_TOTAL_BYTES = 500 * 1024 * 1024;

const BUILTIN_IGNORED_DIRS = new Set([
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

export interface LocalSourcePackage {
  readonly archivePath: string;
  readonly commitSha: string | null;
  readonly exclusions: ReadonlyArray<ManifestExclusion>;
  cleanup(): Promise<void>;
}

export async function createLocalSourcePackage(sourceRoot: string): Promise<LocalSourcePackage> {
  const root = path.resolve(sourceRoot);
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory()) {
    throw new Error(`Local source is not a directory: ${sourceRoot}`);
  }

  const tmp = await mkdtemp(path.join(tmpdir(), "vibeshield-source-"));
  const staging = path.join(tmp, "staging");
  const archivePath = path.join(tmp, "source.tar");
  await mkdir(staging, { recursive: true });

  const { files, exclusions, commitSha } = await collectLocalFiles(root);
  for (const rel of files) {
    const from = path.join(root, rel);
    const to = path.join(staging, rel);
    await mkdir(path.dirname(to), { recursive: true });
    await copyFile(from, to);
  }

  await execFileP("tar", ["-cf", archivePath, "-C", staging, "."], {
    env: { ...process.env, COPYFILE_DISABLE: "1" },
  });

  return {
    archivePath,
    commitSha,
    exclusions,
    cleanup: async () => {
      await rm(tmp, { recursive: true, force: true });
    },
  };
}

async function collectLocalFiles(
  root: string,
): Promise<{ files: string[]; exclusions: ManifestExclusion[]; commitSha: string | null }> {
  if (await hasOwnGitDir(root)) {
    return collectGitFilteredFiles(root);
  }
  return { ...(await collectBuiltinFilteredFiles(root)), commitSha: null };
}

async function collectGitFilteredFiles(
  root: string,
): Promise<{ files: string[]; exclusions: ManifestExclusion[]; commitSha: string | null }> {
  const listed = await gitZ(root, ["ls-files", "-c", "-o", "--exclude-standard", "-z"]);
  const files = new Set<string>();
  for (const rel of listed) {
    if (isSafeRelativePath(rel)) {
      files.add(rel);
    }
  }
  for (const rel of await collectEnvFiles(root)) {
    files.add(rel);
  }

  const exclusions: ManifestExclusion[] = [];
  for (const rel of await gitZ(root, ["ls-files", "-o", "-i", "--exclude-standard", "-z"])) {
    if (!files.has(rel) && isSafeRelativePath(rel)) {
      exclusions.push({ path: rel, reason: "git-ignored" });
    }
  }
  exclusions.push({ path: ".git", reason: "builtin-ignore" });

  const limited = await applyLimits(root, [...files].sort(), exclusions);
  return { ...limited, commitSha: await gitText(root, ["rev-parse", "HEAD"]) };
}

async function collectBuiltinFilteredFiles(
  root: string,
): Promise<{ files: string[]; exclusions: ManifestExclusion[] }> {
  const files: string[] = [];
  const exclusions: ManifestExclusion[] = [];

  const walk = async (absDir: string, relDir: string): Promise<void> => {
    const entries = await readdir(absDir, { withFileTypes: true });
    for (const entry of entries) {
      const rel = toPosixPath(path.join(relDir, entry.name));
      if (!isSafeRelativePath(rel)) {
        continue;
      }
      const abs = path.join(root, rel);
      if (entry.isDirectory()) {
        if (BUILTIN_IGNORED_DIRS.has(entry.name)) {
          exclusions.push({ path: rel, reason: "builtin-ignore" });
          continue;
        }
        await walk(abs, rel);
        continue;
      }
      if (entry.isSymbolicLink()) {
        exclusions.push({ path: rel, reason: "symlink-escape" });
        continue;
      }
      if (entry.isFile()) {
        files.push(rel);
      }
    }
  };

  await walk(root, "");
  return applyLimits(root, files.sort(), exclusions);
}

async function applyLimits(
  root: string,
  candidates: string[],
  exclusions: ManifestExclusion[],
): Promise<{ files: string[]; exclusions: ManifestExclusion[] }> {
  const files: string[] = [];
  let totalBytes = 0;

  for (const rel of candidates) {
    const st = await lstat(path.join(root, rel));
    if (st.isSymbolicLink()) {
      exclusions.push({ path: rel, reason: "symlink-escape" });
      continue;
    }
    if (!st.isFile()) {
      continue;
    }
    if (st.size > MAX_FILE_BYTES) {
      exclusions.push({ path: rel, reason: "too_large" });
      continue;
    }
    if (files.length >= MAX_FILES || totalBytes + st.size > MAX_TOTAL_BYTES) {
      exclusions.push({ path: rel, reason: "truncated" });
      continue;
    }
    files.push(rel);
    totalBytes += st.size;
  }

  return { files, exclusions };
}

async function collectEnvFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (absDir: string, relDir: string): Promise<void> => {
    const entries = await readdir(absDir, { withFileTypes: true });
    for (const entry of entries) {
      const rel = toPosixPath(path.join(relDir, entry.name));
      if (!isSafeRelativePath(rel)) {
        continue;
      }
      if (entry.isDirectory()) {
        if (BUILTIN_IGNORED_DIRS.has(entry.name)) {
          continue;
        }
        await walk(path.join(root, rel), rel);
        continue;
      }
      if (entry.isFile() && (entry.name === ".env" || entry.name.startsWith(".env."))) {
        out.push(rel);
      }
    }
  };
  await walk(root, "");
  return out;
}

async function hasOwnGitDir(root: string): Promise<boolean> {
  try {
    const st = await lstat(path.join(root, ".git"));
    return st.isDirectory() || st.isFile();
  } catch {
    return false;
  }
}

async function gitZ(cwd: string, args: string[]): Promise<string[]> {
  const { stdout } = await execFileP("git", args, { cwd, maxBuffer: 64 * 1024 * 1024 });
  return stdout
    .split("\0")
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
    .map(toPosixPath);
}

async function gitText(cwd: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await execFileP("git", args, { cwd, maxBuffer: 1024 * 1024 });
    const value = stdout.trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

function toPosixPath(p: string): string {
  return p.split(path.sep).join("/");
}

function isSafeRelativePath(rel: string): boolean {
  return (
    rel.length > 0 &&
    !rel.includes("\0") &&
    !rel.includes("\\") &&
    !path.posix.isAbsolute(rel) &&
    rel.split("/").every((part) => part !== "" && part !== "." && part !== "..")
  );
}
