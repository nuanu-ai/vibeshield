import type {
  BaselineSummaryArtifact,
  InventoryArtifact,
  PiContextPackArtifact,
} from "../artifacts/contracts.js";
import type { ArtifactStore } from "../artifacts/store.js";
import { ScanStageError } from "../run/errors.js";

const contextLimits = {
  configFiles: 80,
  infraFiles: 80,
  manifestFiles: 80,
  packageAndLockFiles: 120,
  sourceIndexDirectories: 80,
  sourceIndexSampleFiles: 6,
  topLevelDirectories: 120,
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

  const contextPack: PiContextPackArtifact = {
    inventory: {
      config_files: configFiles(input.inventory).slice(0, contextLimits.configFiles),
      github_actions_workflows: githubActionsWorkflows,
      iac_candidates: iacCandidates,
      infra_files: infraFiles(input.inventory).slice(0, contextLimits.infraFiles),
      language_summary: languageSummary(input.inventory),
      manifest_files: input.inventory.summary.manifest_files.slice(0, contextLimits.manifestFiles),
      package_and_lock_files: packageAndLockFiles(input.inventory).slice(
        0,
        contextLimits.packageAndLockFiles,
      ),
      source_index: sourceIndex(input.inventory),
      summary: input.inventory.summary,
      top_level_directories: topLevelDirectories(input.inventory).slice(
        0,
        contextLimits.topLevelDirectories,
      ),
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

function configFiles(inventory: InventoryArtifact): string[] {
  return inventory.files
    .map((file) => file.path)
    .filter((filePath) => {
      const normalized = filePath.toLowerCase();
      const basename = normalized.split("/").at(-1) ?? normalized;
      return !isLowSignalPath(normalized) && isConfigLikeFile(basename);
    })
    .sort((left, right) => left.localeCompare(right));
}

function infraFiles(inventory: InventoryArtifact): string[] {
  return inventory.files
    .map((file) => file.path)
    .filter((filePath) => {
      const normalized = filePath.toLowerCase();
      return !isLowSignalPath(normalized) && isInfraLikePath(normalized);
    })
    .sort((left, right) => left.localeCompare(right));
}

function sourceIndex(
  inventory: InventoryArtifact,
): PiContextPackArtifact["inventory"]["source_index"] {
  const byDirectory = new Map<
    string,
    {
      directory: string;
      file_count: number;
      languages: Set<string>;
      sample_files: string[];
      total_loc: number;
    }
  >();

  for (const file of inventory.files) {
    const normalized = file.path.toLowerCase();
    const basename = normalized.split("/").at(-1) ?? normalized;
    if (file.type !== "file" || isLowSignalPath(normalized) || !isSourceLikeFile(basename)) {
      continue;
    }

    const directory = sourceIndexDirectory(file.path);
    const language = languageForPath(file.path);
    const current =
      byDirectory.get(directory) ??
      ({
        directory,
        file_count: 0,
        languages: new Set<string>(),
        sample_files: [],
        total_loc: 0,
      } satisfies {
        directory: string;
        file_count: number;
        languages: Set<string>;
        sample_files: string[];
        total_loc: number;
      });

    current.file_count += 1;
    if (language !== undefined) {
      current.languages.add(language);
    }
    if (file.line_count !== undefined) {
      current.total_loc += file.line_count;
    }
    if (current.sample_files.length < contextLimits.sourceIndexSampleFiles) {
      current.sample_files.push(file.path);
    }
    byDirectory.set(directory, current);
  }

  return [...byDirectory.values()]
    .sort(
      (left, right) =>
        right.file_count - left.file_count || left.directory.localeCompare(right.directory),
    )
    .slice(0, contextLimits.sourceIndexDirectories)
    .map((record) => ({
      directory: record.directory,
      file_count: record.file_count,
      languages: [...record.languages].sort((left, right) => left.localeCompare(right)),
      sample_files: record.sample_files.sort((left, right) => left.localeCompare(right)),
      ...(record.total_loc > 0 ? { total_loc: record.total_loc } : {}),
    }));
}

function sourceIndexDirectory(filePath: string): string {
  const segments = filePath.split("/").slice(0, -1);
  if (segments.length === 0) {
    return ".";
  }
  return segments.slice(0, 2).join("/");
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
      .filter((directory) => directory !== "" && !isLowSignalPath(`${directory}/x`)),
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

function isInfraLikePath(normalizedPath: string): boolean {
  const basename = normalizedPath.split("/").at(-1) ?? normalizedPath;
  return (
    basename === "dockerfile" ||
    basename.startsWith("docker-compose") ||
    basename === ".gitlab-ci.yml" ||
    normalizedPath.startsWith(".github/workflows/") ||
    basename.endsWith(".tf") ||
    basename.endsWith(".tfvars") ||
    basename.endsWith(".hcl") ||
    basename === "chart.yaml" ||
    basename === "values.yaml" ||
    normalizedPath.includes("/charts/") ||
    normalizedPath.includes("/k8s/") ||
    normalizedPath.includes("/kubernetes/")
  );
}

function isLowSignalPath(normalizedPath: string): boolean {
  return /(^|\/)(\.git|coverage|dist|build|node_modules|vendor)\//.test(normalizedPath);
}

const lockFileBasenames = new Set([
  "bun.lock",
  "bun.lockb",
  "cargo.lock",
  "composer.lock",
  "flake.lock",
  "gemfile.lock",
  "go.sum",
  "gradle.lockfile",
  "mix.lock",
  "npm-shrinkwrap.json",
  "package-lock.json",
  "packages.lock.json",
  "pdm.lock",
  "pipfile.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "uv.lock",
  "yarn.lock",
]);

const manifestBasenames = new Set([
  "build.gradle",
  "build.gradle.kts",
  "cargo.toml",
  "composer.json",
  "gemfile",
  "go.mod",
  "package.json",
  "pipfile",
  "pom.xml",
  "pyproject.toml",
  "requirements.txt",
]);

function isManifestOrLockCandidate(filePath: string): boolean {
  const basename = filePath.split("/").at(-1)?.toLowerCase() ?? filePath.toLowerCase();
  return lockFileBasenames.has(basename) || manifestBasenames.has(basename);
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}
