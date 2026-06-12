import { createHash } from "node:crypto";
import { lstat, readdir, readFile, readlink } from "node:fs/promises";
import path from "node:path";
import type { GitHubRepoReference } from "../run/github-url.js";

export interface RepoInventoryFile {
  line_count?: number;
  path: string;
  sha256?: string;
  size_bytes: number;
  type: "file" | "symlink" | "other";
}

export interface RepoInventoryDirectory {
  path: string;
}

export interface RepoInventory {
  artifact_version: 1;
  generated_at: string;
  generated_by: "vibeshield-phase1";
  kind: "inventory.v1";
  sandbox: {
    id: string;
    inventory_location: "inside_sandbox";
  };
  source: GitHubRepoReference & {
    commit_sha: string | null;
  };
  summary: {
    directory_count: number;
    file_count: number;
    manifest_files: string[];
    total_file_bytes: number;
  };
  directories: RepoInventoryDirectory[];
  files: RepoInventoryFile[];
}

const manifestBasenames = new Set([
  ".env.example",
  "Cargo.toml",
  "Dockerfile",
  "Gemfile",
  "bun.lockb",
  "composer.json",
  "docker-compose.yml",
  "go.mod",
  "package-lock.json",
  "package.json",
  "pnpm-lock.yaml",
  "pyproject.toml",
  "requirements.txt",
  "yarn.lock",
]);

export async function buildRepoInventory(input: {
  commitSha: string | null;
  generatedAt: string;
  repoRoot: string;
  sandboxId: string;
  source: GitHubRepoReference;
}): Promise<RepoInventory> {
  const directories: RepoInventoryDirectory[] = [];
  const files: RepoInventoryFile[] = [];

  await walkRepo(input.repoRoot, "", directories, files);

  directories.sort((left, right) => left.path.localeCompare(right.path));
  files.sort((left, right) => left.path.localeCompare(right.path));

  const manifestFiles = files
    .map((file) => file.path)
    .filter(isManifestPath)
    .sort((left, right) => left.localeCompare(right));

  return {
    artifact_version: 1,
    directories,
    files,
    generated_at: input.generatedAt,
    generated_by: "vibeshield-phase1",
    kind: "inventory.v1",
    sandbox: {
      id: input.sandboxId,
      inventory_location: "inside_sandbox",
    },
    source: {
      ...input.source,
      commit_sha: input.commitSha,
    },
    summary: {
      directory_count: directories.length,
      file_count: files.length,
      manifest_files: manifestFiles,
      total_file_bytes: files.reduce((sum, file) => sum + file.size_bytes, 0),
    },
  };
}

async function walkRepo(
  root: string,
  relativeDirectory: string,
  directories: RepoInventoryDirectory[],
  files: RepoInventoryFile[],
): Promise<void> {
  const absoluteDirectory = path.join(root, relativeDirectory);
  const entries = await readdir(absoluteDirectory, { withFileTypes: true });

  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const relativePath = toPosixPath(path.join(relativeDirectory, entry.name));

    if (relativePath === ".git" || relativePath.startsWith(".git/")) {
      continue;
    }

    const absolutePath = path.join(root, relativePath);
    const stats = await lstat(absolutePath);

    if (stats.isDirectory()) {
      directories.push({ path: relativePath });
      await walkRepo(root, relativePath, directories, files);
      continue;
    }

    if (stats.isFile()) {
      const contents = await readFile(absolutePath);
      files.push({
        ...lineCountField(contents),
        path: relativePath,
        sha256: createHash("sha256").update(contents).digest("hex"),
        size_bytes: stats.size,
        type: "file",
      });
      continue;
    }

    if (stats.isSymbolicLink()) {
      const target = await readlink(absolutePath);
      files.push({
        path: relativePath,
        sha256: createHash("sha256").update(target).digest("hex"),
        size_bytes: stats.size,
        type: "symlink",
      });
      continue;
    }

    files.push({
      path: relativePath,
      size_bytes: stats.size,
      type: "other",
    });
  }
}

function lineCountField(contents: Buffer): { line_count?: number } {
  if (contents.includes(0)) {
    return {};
  }

  const text = contents.toString("utf8");
  if (text.includes("\uFFFD")) {
    return {};
  }

  return {
    line_count: text === "" ? 0 : text.split(/\r\n|\r|\n/).length,
  };
}

function isManifestPath(filePath: string): boolean {
  if (filePath.startsWith(".github/workflows/")) {
    return true;
  }
  return manifestBasenames.has(path.posix.basename(filePath));
}

function toPosixPath(filePath: string): string {
  return filePath.split(path.sep).join("/");
}
