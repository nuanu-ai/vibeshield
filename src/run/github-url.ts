import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readlink, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export interface GitHubRepoReference {
  owner: string;
  repo: string;
  type: "github";
  url: string;
}

export interface LocalRepoSnapshotFile {
  path: string;
  sha256: string;
  size_bytes: number;
  type: "file" | "symlink";
}

export interface LocalRepoSnapshot {
  file_count: number;
  files: LocalRepoSnapshotFile[];
  head_sha: string | null;
  total_file_bytes: number;
}

export interface LocalRepoReference {
  name: string;
  path: string;
  snapshot: LocalRepoSnapshot;
  type: "local";
  url: string;
}

export type SourceReference = GitHubRepoReference | LocalRepoReference;

export type ArtifactSourceReference = GitHubRepoReference | Omit<LocalRepoReference, "snapshot">;

export interface ParseGitHubRepoSuccess {
  repo: GitHubRepoReference;
  success: true;
}

export interface ParseGitHubRepoFailure {
  success: false;
  userMessage: string;
}

export type ParseGitHubRepoResult = ParseGitHubRepoSuccess | ParseGitHubRepoFailure;

export interface ResolveSourceSuccess {
  source: SourceReference;
  success: true;
}

export interface ResolveSourceFailure {
  success: false;
  userMessage: string;
}

export type ResolveSourceResult = ResolveSourceSuccess | ResolveSourceFailure;

const githubScopeError =
  "VibeShield accepts only GitHub repository URLs like https://github.com/owner/repo.";

const sourceScopeError =
  "VibeShield accepts a GitHub repository URL or a local Git worktree root path. " +
  "For local scans, run git init and configure .gitignore before scanning.";

const segmentPattern = /^[A-Za-z0-9_.-]+$/;
const gitMaxBufferBytes = 50 * 1024 * 1024;

export function parseGitHubRepoUrl(input: string): ParseGitHubRepoResult {
  if (looksLikeArchive(input)) {
    return { success: false, userMessage: githubScopeError };
  }

  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    return { success: false, userMessage: githubScopeError };
  }

  if (
    parsed.protocol !== "https:" ||
    parsed.hostname.toLowerCase() !== "github.com" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    return { success: false, userMessage: githubScopeError };
  }

  const segments = parsed.pathname.split("/").filter(Boolean);
  if (segments.length !== 2) {
    return { success: false, userMessage: githubScopeError };
  }

  const [owner, rawRepo] = segments;
  const repo = rawRepo?.endsWith(".git") === true ? rawRepo.slice(0, -4) : rawRepo;

  if (
    owner === undefined ||
    repo === undefined ||
    owner.length === 0 ||
    repo.length === 0 ||
    !segmentPattern.test(owner) ||
    !segmentPattern.test(repo)
  ) {
    return { success: false, userMessage: githubScopeError };
  }

  return {
    repo: {
      owner,
      repo,
      type: "github",
      url: `https://github.com/${owner}/${repo}`,
    },
    success: true,
  };
}

export async function resolveScanSource(input: string): Promise<ResolveSourceResult> {
  const github = parseGitHubRepoUrl(input);
  if (github.success) {
    return { source: github.repo, success: true };
  }

  if (looksLikeArchive(input)) {
    return { success: false, userMessage: sourceScopeError };
  }

  if (looksLikeUnsupportedUrl(input)) {
    return { success: false, userMessage: sourceScopeError };
  }

  return resolveLocalRepoSource(input);
}

export async function resolveLocalRepoSource(input: string): Promise<ResolveSourceResult> {
  const targetPath = localPathFromInput(input);
  const target = path.resolve(targetPath);

  let stats: Awaited<ReturnType<typeof stat>>;
  try {
    stats = await stat(target);
  } catch {
    return {
      success: false,
      userMessage:
        `Local scan target does not exist: ${target}. ` +
        "Pass an existing Git worktree root or a GitHub repository URL.",
    };
  }

  if (!stats.isDirectory()) {
    return {
      success: false,
      userMessage:
        `Local scan target must be a Git worktree directory: ${target}. ` +
        "Pass the repository root directory.",
    };
  }

  const gitRoot = await gitWorktreeRoot(target);
  if (!gitRoot.success) {
    return gitRoot;
  }

  const [targetRealPath, rootRealPath] = await Promise.all([
    realpath(target),
    realpath(gitRoot.root),
  ]);
  if (targetRealPath !== rootRealPath) {
    return {
      success: false,
      userMessage:
        `Local scan target must be the Git worktree root: ${gitRoot.root}. ` +
        "Pass the root directory instead of a subdirectory.",
    };
  }

  const snapshot = await buildLocalRepoSnapshot(rootRealPath);
  return {
    source: {
      name: path.basename(rootRealPath),
      path: rootRealPath,
      snapshot,
      type: "local",
      url: pathToFileURL(rootRealPath).toString(),
    },
    success: true,
  };
}

export function sourceArtifactReference(source: SourceReference): ArtifactSourceReference {
  if (source.type === "github") {
    return source;
  }

  const { snapshot: _snapshot, ...artifactSource } = source;
  return artifactSource;
}

export function localRepoSnapshotsEqual(
  left: LocalRepoSnapshot,
  right: LocalRepoSnapshot,
): boolean {
  if (
    left.file_count !== right.file_count ||
    left.total_file_bytes !== right.total_file_bytes ||
    left.head_sha !== right.head_sha
  ) {
    return false;
  }

  for (let index = 0; index < left.files.length; index += 1) {
    const leftFile = left.files[index];
    const rightFile = right.files[index];
    if (
      leftFile === undefined ||
      rightFile === undefined ||
      leftFile.path !== rightFile.path ||
      leftFile.sha256 !== rightFile.sha256 ||
      leftFile.size_bytes !== rightFile.size_bytes ||
      leftFile.type !== rightFile.type
    ) {
      return false;
    }
  }

  return true;
}

async function buildLocalRepoSnapshot(root: string): Promise<LocalRepoSnapshot> {
  const files = await gitTrackedAndUnignoredFiles(root);
  const snapshotFiles: LocalRepoSnapshotFile[] = [];

  for (const file of files) {
    if (!isSafeRelativeSourcePath(file)) {
      continue;
    }

    const absolutePath = path.join(root, ...file.split("/"));
    const stats = await lstat(absolutePath).catch(() => undefined);
    if (stats === undefined || stats.isDirectory()) {
      continue;
    }

    if (stats.isSymbolicLink()) {
      const target = await readlink(absolutePath);
      snapshotFiles.push({
        path: file,
        sha256: createHash("sha256").update(target).digest("hex"),
        size_bytes: stats.size,
        type: "symlink",
      });
      continue;
    }

    if (!stats.isFile()) {
      continue;
    }

    const contents = await readFile(absolutePath);
    snapshotFiles.push({
      path: file,
      sha256: createHash("sha256").update(contents).digest("hex"),
      size_bytes: stats.size,
      type: "file",
    });
  }

  snapshotFiles.sort((left, right) => left.path.localeCompare(right.path));

  return {
    file_count: snapshotFiles.length,
    files: snapshotFiles,
    head_sha: await gitHeadSha(root),
    total_file_bytes: snapshotFiles.reduce((sum, file) => sum + file.size_bytes, 0),
  };
}

async function gitTrackedAndUnignoredFiles(root: string): Promise<string[]> {
  const result = await runGit(root, [
    "ls-files",
    "-z",
    "--cached",
    "--others",
    "--exclude-standard",
  ]);
  return splitNullSeparated(result.stdout)
    .filter((file) => file !== "")
    .sort((left, right) => left.localeCompare(right));
}

async function gitHeadSha(root: string): Promise<string | null> {
  const result = await runGit(root, ["rev-parse", "--verify", "HEAD"]).catch(() => undefined);
  const head = result?.stdout.trim();
  return head === undefined || head === "" ? null : head;
}

async function gitWorktreeRoot(
  target: string,
): Promise<{ root: string; success: true } | ResolveSourceFailure> {
  const result = await runGit(target, ["rev-parse", "--show-toplevel"]).catch((error: unknown) => {
    if (isCommandNotFoundError(error)) {
      return {
        success: false as const,
        userMessage:
          "Git is required for local path scans. Install Git, run git init in the repository, " +
          "configure .gitignore, and scan the worktree root again.",
      };
    }

    return {
      success: false as const,
      userMessage:
        `Local scan target is not inside a Git worktree: ${target}. ` +
        "Run git init and configure .gitignore before scanning local paths.",
    };
  });

  if ("userMessage" in result) {
    return result;
  }

  const root = result.stdout.trim();
  if (root === "") {
    return {
      success: false,
      userMessage:
        `Could not determine Git worktree root for local scan target: ${target}. ` +
        "Run git init and try again.",
    };
  }

  return { root: path.resolve(root), success: true };
}

function runGit(cwd: string, args: string[]): Promise<{ stderr: string; stdout: string }> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      ["-C", cwd, ...args],
      {
        encoding: "utf8",
        maxBuffer: gitMaxBufferBytes,
      },
      (error, stdout, stderr) => {
        if (error !== null) {
          reject(error);
          return;
        }
        resolve({ stderr, stdout });
      },
    );
  });
}

function localPathFromInput(input: string): string {
  try {
    const url = new URL(input);
    if (url.protocol === "file:") {
      return fileURLToPath(url);
    }
  } catch {
    // Plain filesystem path.
  }

  return input;
}

function splitNullSeparated(value: string): string[] {
  return value.split("\0");
}

function looksLikeArchive(input: string): boolean {
  return /(?:^|[/.])(?:zip|tar|tgz|tar\.gz)$/i.test(input) || input.includes("/archive/");
}

function looksLikeUnsupportedUrl(input: string): boolean {
  try {
    const url = new URL(input);
    return url.protocol !== "file:";
  } catch {
    return false;
  }
}

function isSafeRelativeSourcePath(filePath: string): boolean {
  if (filePath === "" || filePath.includes("\0") || filePath.includes("\\")) {
    return false;
  }
  if (path.posix.isAbsolute(filePath)) {
    return false;
  }
  const normalized = path.posix.normalize(filePath);
  return normalized !== "." && normalized === filePath && !normalized.startsWith("../");
}

function isCommandNotFoundError(error: unknown): boolean {
  return (
    error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}
