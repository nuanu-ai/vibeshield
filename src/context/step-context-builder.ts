import type {
  BaselineSummaryArtifact,
  InventoryArtifact,
  PiContextPackArtifact,
} from "../artifacts/contracts.js";
import type { ArtifactStore } from "../artifacts/store.js";
import { ScanStageError } from "../run/errors.js";

type RepositoryMapPiContextPackArtifact = PiContextPackArtifact & {
  inventory: PiContextPackArtifact["inventory"] & {
    candidate_groups: {
      auth_config_secret_files: string[];
      operation_sink_files: string[];
      source_files: string[];
      storage_integration_infra_files: string[];
      trust_boundary_files: string[];
    };
    package_and_lock_files: string[];
    top_level_directories: string[];
  };
};

const contextLimits = {
  envAndConfigCandidates: 20,
} as const;

const sourceFileExtensions = new Set([
  "c",
  "cc",
  "clj",
  "cljs",
  "cpp",
  "cs",
  "cjs",
  "dart",
  "erl",
  "ex",
  "exs",
  "fs",
  "fsx",
  "go",
  "java",
  "js",
  "jsx",
  "kt",
  "kts",
  "lua",
  "mjs",
  "php",
  "pl",
  "pm",
  "ps1",
  "py",
  "r",
  "rb",
  "rs",
  "scala",
  "sh",
  "swift",
  "ts",
  "tsx",
]);

const sourceContainerDirectories = new Set([
  "app",
  "apps",
  "cmd",
  "packages",
  "services",
  "src",
  "web",
]);

const entrypointRoleDirectories = new Set([
  "api",
  "apis",
  "bin",
  "cli",
  "commands",
  "consumers",
  "controllers",
  "cron",
  "functions",
  "graphql",
  "grpc",
  "handlers",
  "jobs",
  "lambda",
  "lambdas",
  "pages",
  "parsers",
  "queues",
  "resolvers",
  "routes",
  "schedules",
  "server",
  "servers",
  "webhooks",
  "workers",
]);

const entrypointFileStems = new Set([
  "app",
  "application",
  "bootstrap",
  "cli",
  "command",
  "commands",
  "consumer",
  "cron",
  "handler",
  "index",
  "job",
  "lambda_function",
  "main",
  "manage",
  "program",
  "router",
  "routes",
  "schedule",
  "server",
  "startup",
  "worker",
]);

const extensionlessEntrypointFiles = new Set(["artisan", "rakefile"]);

export interface BuildPiContextPackInput {
  baseline: BaselineSummaryArtifact;
  inventory: InventoryArtifact;
  store: ArtifactStore;
}

export interface BuildPiContextPackResult {
  contextPack: RepositoryMapPiContextPackArtifact;
  contextPath: string;
}

export async function buildPiContextPack(
  input: BuildPiContextPackInput,
): Promise<BuildPiContextPackResult> {
  validateInventory(input.inventory);
  validateBaseline(input.baseline);

  const githubActionsWorkflows = input.inventory.files
    .map((file) => file.path)
    .filter((file) => file.startsWith(".github/workflows/"))
    .sort((left, right) => left.localeCompare(right));
  const iacCandidates = input.baseline.summary.iac_candidates.slice(0, 20);
  const envAndConfigCandidates = input.inventory.files
    .map((file) => file.path)
    .filter(isEnvOrConfigCandidate)
    .sort((left, right) => left.localeCompare(right))
    .slice(0, contextLimits.envAndConfigCandidates);
  const entrypointCandidates = candidateEntrypoints(input.inventory).slice(0, 30);
  const authConfigSecretFiles = candidateFilesByKeywords(input.inventory, [
    ".env",
    "api-key",
    "apikey",
    "auth",
    "authorization",
    "credential",
    "guard",
    "jwt",
    "middleware",
    "oauth",
    "permission",
    "policy",
    "role",
    "secret",
    "session",
  ]);
  const operationSinkFiles = candidateFilesByKeywords(input.inventory, [
    "child_process",
    "client",
    "crypto",
    "database",
    "deserialize",
    "exec",
    "fetch",
    "filesystem",
    "http",
    "logger",
    "logging",
    "parse",
    "path",
    "query",
    "random",
    "redirect",
    "render",
    "request",
    "spawn",
    "sql",
    "template",
    "url",
  ]);
  const storageIntegrationInfraFiles = candidateFilesByKeywords(input.inventory, [
    "bucket",
    "cache",
    "compose",
    "database",
    "deploy",
    "docker",
    "helm",
    "infra",
    "integration",
    "k8s",
    "kubernetes",
    "migration",
    "model",
    "orm",
    "prisma",
    "redis",
    "schema",
    "storage",
    "terraform",
  ]);
  const trustBoundaryFiles = uniqueSorted([
    ...entrypointCandidates,
    ...authConfigSecretFiles,
    ...operationSinkFiles.slice(0, 20),
  ]).slice(0, 60);

  const contextPack: RepositoryMapPiContextPackArtifact = {
    inventory: {
      candidate_entrypoints: entrypointCandidates,
      candidate_groups: {
        auth_config_secret_files: authConfigSecretFiles,
        operation_sink_files: operationSinkFiles,
        source_files: sourceFileCandidates(input.inventory).slice(0, 80),
        storage_integration_infra_files: storageIntegrationInfraFiles,
        trust_boundary_files: trustBoundaryFiles,
      },
      env_and_config_candidates: envAndConfigCandidates,
      github_actions_workflows: githubActionsWorkflows,
      iac_candidates: iacCandidates,
      language_summary: languageSummary(input.inventory),
      manifest_files: input.inventory.summary.manifest_files.slice(0, 40),
      package_and_lock_files: packageAndLockFiles(input.inventory).slice(0, 60),
      summary: input.inventory.summary,
      top_level_directories: topLevelDirectories(input.inventory).slice(0, 60),
    },
    repo: {
      commit_sha: input.inventory.source.commit_sha,
      url: input.inventory.source.url,
    },
  };

  const contextPath = await input.store.writeJson({
    data: contextPack,
    id: "pi-context-pack",
    kind: "pi-context-pack",
    relativePath: "outputs/pi-context-pack.json",
  });

  return {
    contextPack,
    contextPath,
  };
}

function validateInventory(inventory: InventoryArtifact): void {
  if (inventory.kind !== "inventory") {
    throw new ScanStageError({
      message: "Invalid inventory artifact schema.",
      stage: "context",
      userMessage: "VibeShield could not build Pi context because inventory is invalid.",
    });
  }
}

function validateBaseline(baseline: BaselineSummaryArtifact): void {
  if (baseline.kind !== "baseline-summary") {
    throw new ScanStageError({
      message: "Invalid baseline-summary artifact schema.",
      stage: "context",
      userMessage: "VibeShield could not build Pi context because baseline-summary is invalid.",
    });
  }
}

function candidateEntrypoints(inventory: InventoryArtifact): string[] {
  const candidates = inventory.files
    .flatMap((file) => {
      const score = entrypointCandidateScore(file.path);
      return score > 0 ? [{ path: file.path, score }] : [];
    })
    .sort((left, right) => right.score - left.score || left.path.localeCompare(right.path))
    .map((candidate) => candidate.path);

  return candidates.length > 0 ? candidates : inventory.summary.manifest_files.slice(0, 5);
}

function candidateFilesByKeywords(inventory: InventoryArtifact, keywords: string[]): string[] {
  return inventory.files
    .flatMap((file) => {
      const score = keywordPathScore(file.path, keywords);
      return score > 0 ? [{ path: file.path, score }] : [];
    })
    .sort((left, right) => right.score - left.score || left.path.localeCompare(right.path))
    .map((candidate) => candidate.path)
    .slice(0, 60);
}

function keywordPathScore(filePath: string, keywords: string[]): number {
  const normalized = filePath.toLowerCase();
  if (isLikelyNonRuntimePath(normalized)) {
    return 0;
  }

  const basename = normalized.split("/").at(-1) ?? normalized;
  let score = isSourceLikeFile(basename) || isConfigLikeFile(basename) ? 1 : 0;

  for (const keyword of keywords) {
    const normalizedKeyword = keyword.toLowerCase();
    if (normalized.includes(normalizedKeyword)) {
      score += basename.includes(normalizedKeyword) ? 3 : 2;
    }
  }

  return score;
}

function sourceFileCandidates(inventory: InventoryArtifact): string[] {
  return inventory.files
    .map((file) => file.path)
    .filter((filePath) => {
      const normalized = filePath.toLowerCase();
      const basename = normalized.split("/").at(-1) ?? normalized;
      return !isLikelyNonRuntimePath(normalized) && isSourceLikeFile(basename);
    })
    .sort((left, right) => left.localeCompare(right));
}

function packageAndLockFiles(inventory: InventoryArtifact): string[] {
  return inventory.files
    .map((file) => file.path)
    .filter(isManifestOrLockCandidate)
    .sort((left, right) => left.localeCompare(right));
}

function topLevelDirectories(inventory: InventoryArtifact): string[] {
  return uniqueSorted(
    inventory.directories
      .map((directory) => directory.path.split("/").slice(0, 2).join("/"))
      .filter((directory) => directory !== "" && !isLikelyNonRuntimePath(`${directory}/x`)),
  );
}

function languageSummary(inventory: InventoryArtifact): Array<{
  file_count: number;
  language: string;
  loc: number;
  source: "inventory";
}> {
  const byLanguage = new Map<string, { file_count: number; language: string; loc: number }>();

  for (const file of inventory.files) {
    if (file.type !== "file" || file.line_count === undefined) {
      continue;
    }
    const language = languageForPath(file.path);
    if (language === undefined) {
      continue;
    }
    const current = byLanguage.get(language) ?? { file_count: 0, language, loc: 0 };
    current.file_count += 1;
    current.loc += file.line_count;
    byLanguage.set(language, current);
  }

  return [...byLanguage.values()]
    .sort((left, right) => right.loc - left.loc || left.language.localeCompare(right.language))
    .slice(0, 20)
    .map((record) => ({ ...record, source: "inventory" }));
}

function languageForPath(filePath: string): string | undefined {
  const basename = filePath.split("/").at(-1)?.toLowerCase() ?? filePath.toLowerCase();
  if (basename === "dockerfile") {
    return "Dockerfile";
  }

  const extension = basename.split(".").at(-1);
  if (extension === undefined) {
    return undefined;
  }

  return (
    {
      c: "C",
      cc: "C++",
      cljs: "ClojureScript",
      clj: "Clojure",
      cpp: "C++",
      cs: "C#",
      cjs: "JavaScript",
      dart: "Dart",
      erl: "Erlang",
      ex: "Elixir",
      exs: "Elixir",
      fs: "F#",
      fsx: "F#",
      go: "Go",
      java: "Java",
      js: "JavaScript",
      jsx: "JavaScript",
      kt: "Kotlin",
      kts: "Kotlin",
      lua: "Lua",
      mjs: "JavaScript",
      php: "PHP",
      pl: "Perl",
      pm: "Perl",
      ps1: "PowerShell",
      py: "Python",
      r: "R",
      rb: "Ruby",
      rs: "Rust",
      scala: "Scala",
      sh: "Shell",
      swift: "Swift",
      ts: "TypeScript",
      tsx: "TypeScript",
    } as Record<string, string | undefined>
  )[extension];
}

function entrypointCandidateScore(filePath: string): number {
  const normalized = filePath.toLowerCase();
  if (isLikelyNonRuntimePath(normalized)) {
    return 0;
  }

  const segments = normalized.split("/");
  const basename = segments.at(-1) ?? normalized;
  const stem = fileStem(basename);
  const isRuntimeFile = isSourceLikeFile(basename) || extensionlessEntrypointFiles.has(basename);

  if (!isRuntimeFile) {
    return 0;
  }

  const directorySegments = segments.slice(0, -1);
  const sourceContainerScore = directorySegments.some((segment) =>
    sourceContainerDirectories.has(segment),
  )
    ? 1
    : 0;
  const roleDirectoryScore = directorySegments.some((segment) =>
    entrypointRoleDirectories.has(segment),
  )
    ? 3
    : 0;
  const stemScore = entrypointFileStems.has(stem) ? 4 : 0;

  return roleDirectoryScore > 0 || stemScore > 0
    ? roleDirectoryScore + stemScore + sourceContainerScore
    : 0;
}

function isSourceLikeFile(basename: string): boolean {
  const extension = basename.split(".").at(-1);
  return extension !== undefined && sourceFileExtensions.has(extension);
}

function isConfigLikeFile(basename: string): boolean {
  return (
    basename.startsWith(".env") ||
    basename.endsWith(".json") ||
    basename.endsWith(".toml") ||
    basename.endsWith(".yaml") ||
    basename.endsWith(".yml") ||
    basename.endsWith(".config") ||
    basename.endsWith(".conf") ||
    basename === "dockerfile" ||
    basename === "makefile"
  );
}

function fileStem(basename: string): string {
  const parts = basename.split(".");
  const extension = parts.at(-1);
  return extension !== undefined && sourceFileExtensions.has(extension)
    ? parts.slice(0, -1).join(".")
    : basename;
}

function isLikelyNonRuntimePath(normalizedPath: string): boolean {
  return /(^|\/)(\.git|coverage|dist|build|node_modules|vendor|test|tests|__tests__|spec|specs|fixtures?|mocks?)\//.test(
    normalizedPath,
  );
}

function isEnvOrConfigCandidate(filePath: string): boolean {
  const basename = filePath.split("/").at(-1)?.toLowerCase() ?? filePath.toLowerCase();
  return (
    basename.startsWith(".env") ||
    basename.includes("secret") ||
    basename.includes("credential") ||
    basename === "vercel.json" ||
    basename === "netlify.toml" ||
    basename === "wrangler.toml"
  );
}

function isManifestOrLockCandidate(filePath: string): boolean {
  const basename = filePath.split("/").at(-1)?.toLowerCase() ?? filePath.toLowerCase();
  return (
    basename.includes("lock") ||
    basename.endsWith(".lock") ||
    basename === "package.json" ||
    basename === "composer.json" ||
    basename === "pyproject.toml" ||
    basename === "requirements.txt" ||
    basename === "go.mod" ||
    basename === "cargo.toml" ||
    basename === "pom.xml" ||
    basename === "build.gradle" ||
    basename === "build.gradle.kts" ||
    basename === "gemfile"
  );
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}
