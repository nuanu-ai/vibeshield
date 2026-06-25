import type { Manifest } from "../domain/manifest.js";
import type { ArtifactRef } from "../domain/run.js";

export const PROGRAM_ANALYSIS_BACKEND_VERSION = "joern@4.0.565";

export type ProgramAnalysisLanguage = "javascript" | "typescript" | "python" | "java" | "go";

export type ProgramAnalysisCoverageState =
  | "checked"
  | "skipped"
  | "failed"
  | "degraded"
  | "partial";

export type ProgramAnalysisCoverageArea =
  | "language_support"
  | "model"
  | "entities"
  | "boundaries"
  | "call_edges"
  | "flows"
  | "component_usage"
  | "ci_iac"
  | "content_assets"
  | "smart_contracts";

export type ProgramAnalysisExtractionKind =
  | "entities"
  | "boundaries"
  | "call_edges"
  | "flows"
  | "component_usage";

export interface ProgramAnalysisBuildInput {
  readonly sourceDir: string;
  readonly manifest: Manifest;
  readonly language?: ProgramAnalysisLanguage;
  readonly outputPath?: string;
}

export interface ProgramAnalysisModelRef {
  readonly backend: "joern";
  readonly backendVersion: string;
  readonly language: ProgramAnalysisLanguage;
  readonly sourceDir: string;
  readonly modelPath: string;
  readonly artifact: ArtifactRef;
  readonly command: ReadonlyArray<string>;
}

export interface ProgramAnalysisExtractionArtifact {
  readonly backend: "joern";
  readonly backendVersion: string;
  readonly kind: ProgramAnalysisExtractionKind;
  readonly language: ProgramAnalysisLanguage;
  readonly modelArtifact: ArtifactRef;
  readonly sliceArtifact: ArtifactRef;
  readonly slicePath: string;
  readonly command: ReadonlyArray<string>;
  readonly parsed: unknown;
}

export interface ProgramAnalysisLanguageCount {
  readonly language: string;
  readonly fileCount: number;
}

export interface ProgramAnalysisLanguageSupport {
  readonly selectedLanguage?: ProgramAnalysisLanguage;
  readonly supported: ReadonlyArray<ProgramAnalysisLanguageCount>;
  readonly unsupported: ReadonlyArray<ProgramAnalysisLanguageCount>;
  readonly totalSourceFiles: number;
  readonly coverageState: ProgramAnalysisCoverageState;
  readonly reason?: string;
}

export interface ProgramAnalysisCoverage {
  readonly area: ProgramAnalysisCoverageArea;
  readonly state: ProgramAnalysisCoverageState;
  readonly producer: "joern";
  readonly producerVersion: string;
  readonly coveredCount?: number;
  readonly totalCount?: number;
  readonly reason?: string;
}

export interface ProgramAnalysisFailure {
  readonly area: ProgramAnalysisCoverageArea;
  readonly reason: string;
}

export interface ProgramAnalysisCoverageInput {
  readonly manifest: Manifest;
  readonly model?: ProgramAnalysisModelRef;
  readonly failures?: ReadonlyArray<ProgramAnalysisFailure>;
}

export interface ProgramAnalysisBackend {
  buildModel(input: ProgramAnalysisBuildInput): Promise<ProgramAnalysisModelRef>;
  extractEntities(model: ProgramAnalysisModelRef): Promise<ProgramAnalysisExtractionArtifact>;
  extractBoundaries(model: ProgramAnalysisModelRef): Promise<ProgramAnalysisExtractionArtifact>;
  extractCallEdges(model: ProgramAnalysisModelRef): Promise<ProgramAnalysisExtractionArtifact>;
  extractFlows(model: ProgramAnalysisModelRef): Promise<ProgramAnalysisExtractionArtifact>;
  extractComponentUsage(model: ProgramAnalysisModelRef): Promise<ProgramAnalysisExtractionArtifact>;
  reportCoverage(input: ProgramAnalysisCoverageInput): ReadonlyArray<ProgramAnalysisCoverage>;
}

export class ProgramAnalysisBackendError extends Error {
  override readonly name = "ProgramAnalysisBackendError";
  readonly code: string;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(code: string, message: string, details?: Readonly<Record<string, unknown>>) {
    super(message);
    this.code = code;
    if (details !== undefined) {
      this.details = details;
    }
  }
}

const SUPPORTED_EXTENSIONS = new Map<string, ProgramAnalysisLanguage>([
  [".cjs", "javascript"],
  [".js", "javascript"],
  [".jsx", "javascript"],
  [".mjs", "javascript"],
  [".cts", "typescript"],
  [".mts", "typescript"],
  [".ts", "typescript"],
  [".tsx", "typescript"],
  [".java", "java"],
  [".py", "python"],
  [".go", "go"],
]);

const UNSUPPORTED_SOURCE_EXTENSIONS = new Map<string, string>([
  [".c", "c"],
  [".cc", "c++"],
  [".cpp", "c++"],
  [".cs", "csharp"],
  [".kt", "kotlin"],
  [".php", "php"],
  [".rb", "ruby"],
  [".rs", "rust"],
  [".scala", "scala"],
  [".swift", "swift"],
]);

export function languageSupportFromManifest(manifest: Manifest): ProgramAnalysisLanguageSupport {
  const supported = new Map<ProgramAnalysisLanguage, number>();
  const unsupported = new Map<string, number>();

  for (const file of manifest.files) {
    const ext = extensionOf(file.path);
    const supportedLanguage = SUPPORTED_EXTENSIONS.get(ext);
    if (supportedLanguage !== undefined) {
      supported.set(supportedLanguage, (supported.get(supportedLanguage) ?? 0) + 1);
      continue;
    }
    const unsupportedLanguage = UNSUPPORTED_SOURCE_EXTENSIONS.get(ext);
    if (unsupportedLanguage !== undefined) {
      unsupported.set(unsupportedLanguage, (unsupported.get(unsupportedLanguage) ?? 0) + 1);
    }
  }

  const supportedCounts = sortedCounts(supported);
  const unsupportedCounts = sortedCounts(unsupported);
  const selectedLanguage = selectLanguage(manifest.files.map((file) => file.path));
  const totalSourceFiles = countFiles(supportedCounts) + countFiles(unsupportedCounts);
  const coverageState = languageCoverageState(supportedCounts.length, unsupportedCounts.length);
  const reason = languageCoverageReason(supportedCounts, unsupportedCounts);
  const support = {
    supported: supportedCounts,
    unsupported: unsupportedCounts,
    totalSourceFiles,
    coverageState,
    ...(selectedLanguage === undefined ? {} : { selectedLanguage }),
  };

  return withOptionalReason(support, reason);
}

function extensionOf(repoPath: string): string {
  const name = repoPath.split("/").at(-1) ?? repoPath;
  const index = name.lastIndexOf(".");
  return index < 0 ? "" : name.slice(index).toLowerCase();
}

function sortedCounts(counts: ReadonlyMap<string, number>): ProgramAnalysisLanguageCount[] {
  return [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([language, fileCount]) => ({ language, fileCount }));
}

function countFiles(counts: ReadonlyArray<ProgramAnalysisLanguageCount>): number {
  return counts.reduce((total, item) => total + item.fileCount, 0);
}

function selectLanguage(paths: ReadonlyArray<string>): ProgramAnalysisLanguage | undefined {
  const scores = new Map<ProgramAnalysisLanguage, number>();
  for (const repoPath of paths) {
    const language = SUPPORTED_EXTENSIONS.get(extensionOf(repoPath));
    if (language === undefined) {
      continue;
    }
    const score = languageSelectionScore(language, repoPath);
    scores.set(language, (scores.get(language) ?? 0) + score);
  }
  let selected: ProgramAnalysisLanguage | undefined;
  let selectedScore = 0;
  for (const language of ["typescript", "javascript", "java", "python", "go"] as const) {
    const score = scores.get(language) ?? 0;
    if (score > selectedScore) {
      selected = language;
      selectedScore = score;
    }
  }
  return selected;
}

function languageSelectionScore(language: ProgramAnalysisLanguage, repoPath: string): number {
  if ((language === "javascript" || language === "typescript") && isLikelyStaticAsset(repoPath)) {
    return 1;
  }
  return 10;
}

function isLikelyStaticAsset(repoPath: string): boolean {
  const normalized = repoPath.toLowerCase().replaceAll("\\", "/");
  const parts = normalized.split("/");
  const assetDirectories = new Set([
    "assets",
    "build",
    "dist",
    "docs",
    "public",
    "static",
    "template",
    "templates",
    "vendor",
    "wwwroot",
  ]);
  return (
    parts.some((part) => assetDirectories.has(part)) ||
    normalized.includes("-doc/") ||
    normalized.endsWith(".min.js") ||
    normalized.endsWith(".bundle.js")
  );
}

function languageCoverageState(
  supportedLanguageCount: number,
  unsupportedLanguageCount: number,
): ProgramAnalysisCoverageState {
  if (supportedLanguageCount > 0 && unsupportedLanguageCount > 0) {
    return "partial";
  }
  if (supportedLanguageCount > 0) {
    return "checked";
  }
  if (unsupportedLanguageCount > 0) {
    return "degraded";
  }
  return "skipped";
}

function languageCoverageReason(
  supported: ReadonlyArray<ProgramAnalysisLanguageCount>,
  unsupported: ReadonlyArray<ProgramAnalysisLanguageCount>,
): string | undefined {
  if (supported.length === 0 && unsupported.length === 0) {
    return "No JS, TS, Java, Python, Go, or known unsupported source files were present in the snapshot.";
  }
  if (supported.length === 0) {
    return `No supported JS/TS/Java/Python/Go source files found; unsupported source languages: ${formatCounts(unsupported)}.`;
  }
  if (unsupported.length > 0) {
    return `Some source languages are not supported by Deep Static v1: ${formatCounts(unsupported)}.`;
  }
  return undefined;
}

function formatCounts(counts: ReadonlyArray<ProgramAnalysisLanguageCount>): string {
  return counts.map((item) => `${item.language}=${item.fileCount}`).join(", ");
}

function withOptionalReason(
  support: Omit<ProgramAnalysisLanguageSupport, "reason">,
  reason: string | undefined,
): ProgramAnalysisLanguageSupport {
  return reason === undefined ? support : { ...support, reason };
}
