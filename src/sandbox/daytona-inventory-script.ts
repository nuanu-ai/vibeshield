import type { GitHubRepoReference } from "../run/github-url.js";

export interface DaytonaInventoryScriptInput {
  artifactPath: string;
  commitSha: string | null;
  generatedAt: string;
  repoRoot: string;
  sandboxId: string;
  source: GitHubRepoReference;
}

export function buildDaytonaInventoryScript(input: DaytonaInventoryScriptInput): string {
  const config = JSON.stringify(input);

  return `
import { createHash } from "node:crypto";
import { lstat, mkdir, readdir, readFile, readlink, writeFile } from "node:fs/promises";
import path from "node:path";

const config = ${config};
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

function toPosixPath(filePath) {
  return filePath.split(path.sep).join("/");
}

function isManifestPath(filePath) {
  if (filePath.startsWith(".github/workflows/")) {
    return true;
  }
  return manifestBasenames.has(path.posix.basename(filePath));
}

async function walkRepo(root, relativeDirectory, directories, files) {
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

async function main() {
  const directories = [];
  const files = [];
  await walkRepo(config.repoRoot, "", directories, files);

  directories.sort((left, right) => left.path.localeCompare(right.path));
  files.sort((left, right) => left.path.localeCompare(right.path));

  const manifestFiles = files
    .map((file) => file.path)
    .filter(isManifestPath)
    .sort((left, right) => left.localeCompare(right));

  const inventory = {
    artifact_version: 1,
    directories,
    files,
    generated_at: config.generatedAt,
    generated_by: "vibeshield-phase0",
    sandbox: {
      id: config.sandboxId,
      inventory_location: "inside_sandbox",
    },
    source: {
      ...config.source,
      commit_sha: config.commitSha,
    },
    summary: {
      directory_count: directories.length,
      file_count: files.length,
      manifest_files: manifestFiles,
      total_file_bytes: files.reduce((sum, file) => sum + file.size_bytes, 0),
    },
  };

  await mkdir(path.dirname(config.artifactPath), { recursive: true });
  await writeFile(config.artifactPath, JSON.stringify(inventory, null, 2) + "\\n", "utf8");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : String(error));
  process.exit(1);
});
`;
}
