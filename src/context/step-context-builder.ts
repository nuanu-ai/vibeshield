import type {
  BaselineSummaryArtifact,
  InventoryArtifact,
  PiContextPackArtifact,
} from "../artifacts/contracts.js";
import type { ArtifactStore } from "../artifacts/store.js";
import { ScanStageError } from "../run/errors.js";

const contextBudget = {
  max_data_flows: 60,
  max_entry_points: 50,
  max_fact_gaps: 10,
  max_important_files: 20,
  max_sensitive_sinks: 80,
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
  contextPack: PiContextPackArtifact;
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
    .slice(0, contextBudget.max_important_files);

  const contextPack: PiContextPackArtifact = {
    budget: contextBudget,
    inventory: {
      candidate_entrypoints: candidateEntrypoints(input.inventory).slice(0, 30),
      env_and_config_candidates: envAndConfigCandidates,
      github_actions_workflows: githubActionsWorkflows,
      iac_candidates: iacCandidates,
      manifest_files: input.inventory.summary.manifest_files.slice(0, 40),
      summary: input.inventory.summary,
    },
    repo: {
      commit_sha: input.inventory.source.commit_sha,
      url: input.inventory.source.url,
    },
  };

  const contextPath = await input.store.writeJson({
    data: contextPack,
    id: "pi-context-pack",
    kind: "pi-context-pack.v1",
    relativePath: "outputs/pi-context-pack.v1.json",
    version: 1,
  });

  return {
    contextPack,
    contextPath,
  };
}

function validateInventory(inventory: InventoryArtifact): void {
  if (inventory.kind !== "inventory.v1" || inventory.artifact_version !== 1) {
    throw new ScanStageError({
      message: "Invalid inventory artifact schema/version.",
      stage: "context",
      userMessage: "VibeShield could not build Pi context because inventory.v1 is invalid.",
    });
  }
}

function validateBaseline(baseline: BaselineSummaryArtifact): void {
  if (baseline.kind !== "baseline-summary.v1" || baseline.artifact_version !== 1) {
    throw new ScanStageError({
      message: "Invalid baseline-summary artifact schema/version.",
      stage: "context",
      userMessage: "VibeShield could not build Pi context because baseline-summary.v1 is invalid.",
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
