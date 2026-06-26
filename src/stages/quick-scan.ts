import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { jsonrepair } from "jsonrepair";
import type { ActionCandidate, RemediationAction } from "../domain/action.js";
import { type Verdict, verdictLabel } from "../domain/assessment.js";
import type { CoverageEntry } from "../domain/coverage-summary.js";
import type { Evidence, RedactedRawArtifact } from "../domain/evidence.js";
import type { Finding, FindingCategory, FindingCluster, Severity } from "../domain/finding.js";
import type { PlannedCheck, RepositoryInventory, ScanPlan } from "../domain/inventory.js";
import type { Manifest } from "../domain/manifest.js";
import { summarizeManifest, summarizeToolchain } from "../domain/manifest-summary.js";
import type { ArtifactRef, SourceInput, StageId } from "../domain/run.js";
import { buildAssessment, type RankedAction } from "../domain/security-assessment.js";
import type { StageContext, StageDefinition, StageResult } from "../pipeline/stage-definition.js";
import type {
  ModelEnhanceActionInput,
  ModelEnhanceBatchInput,
  ModelEnhanceCount,
} from "../ports/model-provider.js";
import type { ExecResult } from "../ports/sandbox-runtime.js";
import {
  renderDeepHtmlReport,
  renderDeepMarkdownReport,
  renderDeepReportJson,
} from "../reporting/deep-report.js";
import {
  actionCardHtml,
  actionLocationsForReport,
  coverageCheckLabel,
  coverageDetailsHtml,
  coverageRowFromQuickCheck,
  coverageStatusLabel,
  footerMetaLine,
  noteHtml,
  renderReportDocument,
  repositoryName,
  sectionHeadingHtml,
  statsHtml,
  verdictBannerHtml,
  verdictSubline,
} from "../reporting/report-html.js";
import {
  DEEP_STATIC_STAGE_ID,
  type DeepStaticData,
  deepStaticStage,
  HYPOTHESIS_ENRICH_STAGE_ID,
  type HypothesisEnrichData,
  hypothesisEnrichStage,
} from "./deep-static.js";
import { createLocalSourcePackage } from "./local-source-package.js";
import {
  GITLEAKS_REPORT_PATH,
  LOCAL_SOURCE_TAR,
  MANIFEST_PATH,
  MANIFEST_SCRIPT_PATH,
  OPENGREP_REPORT_PATH,
  OPENGREP_RULES_PATH,
  ORIGIN_PATH,
  OSV_VULN_REPORT_PATH,
  SOURCE_DIR,
  SOURCE_FILTER_PATH,
  SYFT_SBOM_PATH,
  TOOLCHAIN_FRESHNESS_PATH,
  TRIVY_CACHE_DIR,
  TRIVY_CONFIG_REPORT_PATH,
  TRIVY_VULN_REPORT_PATH,
  WORK_DIR,
} from "./paths.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SOURCE_TIMEOUT_MS = 5 * 60 * 1000;
const MODEL_ACTION_LIMIT = 10;
const MODEL_FINDING_LIMIT_PER_ACTION = 10;
const MODEL_AFFECTED_FILE_LIMIT_PER_ACTION = 20;
const MODEL_SNIPPET_CHAR_LIMIT = 500;
const MODEL_SUMMARY_BUCKET_LIMIT = 12;
const TOOLCHAIN_REFRESH_TIMEOUT_MS = 5 * 60 * 1000;
const SCANNER_TIMEOUT_MS = 2 * 60 * 1000;
const MODEL_REMEDIATION_CONCURRENCY = 2;

const SCANNER_STAGE_IDS = [
  "scan.secrets.gitleaks",
  "scan.code.opengrep",
  "scan.sbom.syft",
  "scan.dependencies.trivy",
  "scan.dependencies.osv",
  "scan.github-actions.actionlint",
  "scan.github-actions.zizmor",
  "scan.iac.trivy-config",
] as const;

type ScannerStageId = (typeof SCANNER_STAGE_IDS)[number];

export interface QuickScanStagesOptions {
  readonly deep?: boolean;
}

export function quickScanStages(options: QuickScanStagesOptions = {}): StageDefinition[] {
  const deep = options.deep ?? false;
  return [
    sourceResolveStage(),
    toolchainRefreshStage(),
    snapshotManifestStage(),
    inventoryDetectStage(),
    gitleaksStage(),
    opengrepStage(),
    syftStage(),
    trivyDependencyStage(),
    osvDependencyStage(),
    actionlintStage(),
    zizmorStage(),
    trivyConfigStage(),
    normalizeStage(),
    correlateStage(),
    actionsStage(),
    // Deterministic deep analysis runs with the other scans; the LLM steps
    // (remediation copy, hypothesis enrichment) run last so the report is the
    // final thing assembled once every scan has completed.
    ...(deep ? [deepStaticStage()] : []),
    remediationStage(),
    ...(deep ? [hypothesisEnrichStage()] : []),
    reportStage({ deep }),
  ];
}

interface SourceResolveData {
  readonly sourceDir: string;
}

interface ToolchainFreshnessData {
  readonly tools: ReadonlyArray<ToolchainFreshnessRecord>;
}

interface ToolchainFreshnessRecord {
  readonly tool: string;
  readonly dbDate?: string;
  readonly dbStale?: boolean;
}

interface ManifestData {
  readonly manifest: Manifest;
  readonly manifestArtifact: ArtifactRef;
}

interface InventoryData {
  readonly inventory: RepositoryInventory;
  readonly scanPlan: ScanPlan;
}

interface GitleaksData {
  readonly check: "secrets.gitleaks";
  readonly coverage: CoverageEntry;
  readonly rawArtifact: RedactedRawArtifact;
  readonly records: GitleaksRecord[];
}

interface ScannerRunData {
  readonly check: string;
  readonly tool: string;
  readonly coverage: CoverageEntry;
  readonly rawArtifact?: RedactedRawArtifact;
  readonly recordCount: number;
  readonly candidates: ScannerCandidate[];
}

interface ScannerCandidate {
  readonly check: string;
  readonly tool: string;
  readonly ruleId?: string;
  readonly message?: string;
  readonly filePath?: string;
  readonly startLine?: number;
  readonly severity?: string;
  readonly metadata?: Readonly<Record<string, string>>;
}

interface ScannerCandidateFields {
  readonly ruleId?: string | undefined;
  readonly message?: string | undefined;
  readonly filePath?: string | undefined;
  readonly startLine?: number | undefined;
  readonly severity?: string | undefined;
  readonly metadata?: Readonly<Record<string, string>> | undefined;
}

interface NormalizeData {
  readonly evidence: Evidence[];
  readonly findings: Finding[];
}

interface CorrelateData {
  readonly clusters: FindingCluster[];
}

interface ActionsData {
  readonly candidates: ActionCandidate[];
  readonly verdict: Verdict;
}

interface RemediationData {
  readonly rankedActions: RankedAction[];
}

interface ReportData {
  readonly assessment: ReturnType<typeof buildAssessment>;
  readonly reportArtifacts: ArtifactRef[];
  readonly reportPaths: Readonly<Record<string, string>>;
}

interface GitleaksRecord {
  readonly RuleID?: string;
  readonly Description?: string;
  readonly File?: string;
  readonly StartLine?: number;
  readonly EndLine?: number;
  readonly Secret?: string;
  readonly Match?: string;
  readonly Fingerprint?: string;
  readonly Tags?: string[];
  readonly [key: string]: unknown;
}

function sourceResolveStage(): StageDefinition {
  return {
    id: "source.resolve",
    version: "1",
    dependencies: [],
    inputs: [],
    outputs: [],
    required: true,
    timeoutMs: SOURCE_TIMEOUT_MS,
    run: async (ctx) => {
      await execRequired(ctx, ["node", "--version"], "toolchain preflight: node");
      await execRequired(ctx, ["git", "--version"], "toolchain preflight: git");
      await execRequired(ctx, ["gitleaks", "version"], "toolchain preflight: gitleaks");
      await execRequired(
        ctx,
        ["vibeshield-osv-scan", "--help"],
        "toolchain preflight: osv scanner",
      );
      await execRequired(ctx, ["mkdir", "-p", WORK_DIR], "create work directory");
      await execRequired(ctx, ["rm", "-rf", SOURCE_DIR], "clear previous source directory");
      if (ctx.source.kind === "github") {
        await ctx.session.uploadBytes(ORIGIN_PATH, jsonBytes(ctx.source));
        await execRequired(
          ctx,
          ["git", "clone", "--depth", "1", ctx.source.url, SOURCE_DIR],
          "clone GitHub repository",
        );
      } else {
        const pkg = await createLocalSourcePackage(ctx.source.path);
        try {
          await ctx.session.uploadBytes(
            ORIGIN_PATH,
            jsonBytes({
              ...ctx.source,
              ...(pkg.originUrl === undefined ? {} : { originUrl: pkg.originUrl }),
            }),
          );
          await ctx.session.upload(pkg.archivePath, LOCAL_SOURCE_TAR);
          await ctx.session.uploadBytes(
            SOURCE_FILTER_PATH,
            jsonBytes({
              mode: "pre-filtered",
              commitSha: pkg.commitSha,
              exclusions: pkg.exclusions,
            }),
          );
          await execRequired(ctx, ["mkdir", "-p", SOURCE_DIR], "create source directory");
          await execRequired(
            ctx,
            ["tar", "-xf", LOCAL_SOURCE_TAR, "-C", SOURCE_DIR],
            "extract local source package",
          );
        } finally {
          await pkg.cleanup();
        }
      }

      return success({ sourceDir: SOURCE_DIR } satisfies SourceResolveData);
    },
  };
}

function toolchainRefreshStage(): StageDefinition {
  return {
    id: "toolchain.refresh",
    version: "1",
    dependencies: ["source.resolve"],
    inputs: [],
    outputs: [],
    required: true,
    timeoutMs: TOOLCHAIN_REFRESH_TIMEOUT_MS,
    run: async (ctx) => {
      let refreshResult: ExecResult | undefined;
      let refreshError: string | undefined;
      try {
        refreshResult = await ctx.session.exec([
          "trivy",
          "image",
          "--download-db-only",
          "--cache-dir",
          TRIVY_CACHE_DIR,
        ]);
      } catch (error) {
        refreshError = errorMessage(error);
      }

      const dbDate = await readTrivyDbDate(ctx);
      const refreshFailed =
        refreshError !== undefined || refreshResult === undefined || refreshResult.exitCode !== 0;
      const freshness: ToolchainFreshnessData = {
        tools: [
          {
            tool: "trivy",
            ...(dbDate !== undefined ? { dbDate } : {}),
            dbStale: refreshFailed || dbDate === undefined,
          },
        ],
      };
      await ctx.session.uploadBytes(TOOLCHAIN_FRESHNESS_PATH, jsonBytes(freshness));
      return success({ tools: freshness.tools });
    },
  };
}

function snapshotManifestStage(): StageDefinition {
  return {
    id: "snapshot.manifest",
    version: "1",
    dependencies: ["source.resolve", "toolchain.refresh"],
    inputs: [],
    outputs: ["manifest"],
    required: true,
    run: async (ctx) => {
      const source = readInput<SourceResolveData>(ctx, "source.resolve");
      await ctx.session.uploadBytes(MANIFEST_SCRIPT_PATH, encoder.encode(manifestScript()));
      await execRequired(
        ctx,
        [
          "node",
          MANIFEST_SCRIPT_PATH,
          source.sourceDir,
          ORIGIN_PATH,
          SOURCE_FILTER_PATH,
          MANIFEST_PATH,
          ctx.toolchainImageTag,
          TOOLCHAIN_FRESHNESS_PATH,
        ],
        "write snapshot manifest",
      );

      const manifestBytes = await ctx.session.read(MANIFEST_PATH);
      const manifest = parseJson<Manifest>(manifestBytes, "manifest.json");
      const stored = await ctx.artifacts.store(manifestBytes);
      const artifact = artifactRef(stored.sha256, "manifest", stored.bytes);
      await writeFile(path.join(ctx.runDir, "manifest.json"), manifestBytes);
      return success(
        {
          manifest,
          manifestArtifact: artifact,
        } satisfies ManifestData,
        [artifact],
      );
    },
  };
}

function inventoryDetectStage(): StageDefinition {
  return {
    id: "inventory.detect",
    version: "1",
    dependencies: ["snapshot.manifest"],
    inputs: ["manifest"],
    outputs: [],
    required: true,
    run: async (ctx) => {
      const { manifest } = readInput<ManifestData>(ctx, "snapshot.manifest");
      const inventory = inventoryFromManifest(manifest);
      return success({
        inventory,
        scanPlan: scanPlanFromInventory(inventory),
      } satisfies InventoryData);
    },
  };
}

function gitleaksStage(): StageDefinition {
  return {
    id: "scan.secrets.gitleaks",
    version: "1",
    dependencies: ["inventory.detect"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    timeoutMs: SCANNER_TIMEOUT_MS,
    run: async (ctx) => {
      const { scanPlan } = readInput<InventoryData>(ctx, "inventory.detect");
      assertApplicableCheck(scanPlan, "secrets.gitleaks");
      const result = await ctx.session.exec([
        "gitleaks",
        "detect",
        "--source",
        SOURCE_DIR,
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        GITLEAKS_REPORT_PATH,
        "--redact=100",
        "--no-banner",
      ]);
      if (result.exitCode !== 0 && result.exitCode !== 1) {
        return failed(`gitleaks failed: ${formatExecFailure(result)}`);
      }

      const rawBytes = await readReportBytes(ctx, result);
      const redactedResult = redactGitleaksReport(rawBytes);
      const redactedBytes = redactedResult.bytes;
      const stored = await ctx.artifacts.store(redactedBytes);
      const rawArtifact: RedactedRawArtifact = {
        blobSha256: stored.sha256,
        tool: "gitleaks",
        format: "gitleaks-json",
        bytes: stored.bytes,
        redacted: true,
      };
      const artifact = artifactRef(stored.sha256, "scanner.raw", stored.bytes);
      if (redactedResult.error !== undefined) {
        return success(
          {
            check: "secrets.gitleaks",
            coverage: {
              check: "secrets.gitleaks",
              status: "failed",
              reason: redactedResult.error,
            },
            rawArtifact,
            records: [],
          } satisfies GitleaksData,
          [artifact],
        );
      }
      return success(
        {
          check: "secrets.gitleaks",
          coverage: { check: "secrets.gitleaks", status: "checked" },
          rawArtifact,
          records: redactedResult.records,
        } satisfies GitleaksData,
        [artifact],
      );
    },
  };
}

function opengrepStage(): StageDefinition {
  return {
    id: "scan.code.opengrep",
    version: "1",
    dependencies: ["inventory.detect"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    timeoutMs: SCANNER_TIMEOUT_MS,
    run: async (ctx) => {
      await ctx.session.uploadBytes(OPENGREP_RULES_PATH, encoder.encode(opengrepRules()));
      return runJsonScanner(ctx, {
        check: "code-patterns.opengrep",
        tool: "opengrep",
        command: [
          "opengrep",
          "scan",
          "--no-git-ignore",
          `--sarif-output=${OPENGREP_REPORT_PATH}`,
          "-f",
          OPENGREP_RULES_PATH,
          SOURCE_DIR,
        ],
        outputPath: OPENGREP_REPORT_PATH,
        format: "sarif-json",
        successfulExitCodes: [0],
        defaultOutput: sarifEmptyReport(),
        candidatesFromRecords: candidatesFromSarif,
      });
    },
  };
}

function syftStage(): StageDefinition {
  return {
    id: "scan.sbom.syft",
    version: "1",
    dependencies: ["inventory.detect"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    timeoutMs: SCANNER_TIMEOUT_MS,
    run: (ctx) =>
      runJsonScanner(ctx, {
        check: "sbom.syft",
        tool: "syft",
        command: ["syft", `dir:${SOURCE_DIR}`, "-o", `cyclonedx-json=${SYFT_SBOM_PATH}`],
        outputPath: SYFT_SBOM_PATH,
        format: "cyclonedx-json",
        successfulExitCodes: [0],
        defaultOutput: "{}",
        candidatesFromRecords: () => [],
      }),
  };
}

function trivyDependencyStage(): StageDefinition {
  return {
    id: "scan.dependencies.trivy",
    version: "1",
    dependencies: ["inventory.detect", "scan.sbom.syft"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    timeoutMs: SCANNER_TIMEOUT_MS,
    run: (ctx) =>
      runJsonScanner(ctx, {
        check: "dependencies.trivy",
        tool: "trivy",
        command: [
          "trivy",
          "sbom",
          "--scanners",
          "vuln",
          "--format",
          "json",
          "--output",
          TRIVY_VULN_REPORT_PATH,
          "--cache-dir",
          TRIVY_CACHE_DIR,
          SYFT_SBOM_PATH,
        ],
        outputPath: TRIVY_VULN_REPORT_PATH,
        format: "trivy-json",
        successfulExitCodes: [0],
        defaultOutput: "{}",
        candidatesFromRecords: candidatesFromTrivy,
      }),
  };
}

function osvDependencyStage(): StageDefinition {
  return {
    id: "scan.dependencies.osv",
    version: "1",
    dependencies: ["inventory.detect"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    timeoutMs: SCANNER_TIMEOUT_MS,
    run: (ctx) =>
      runJsonScanner(ctx, {
        check: "dependencies.osv",
        tool: "osv",
        command: ["vibeshield-osv-scan", "--source", SOURCE_DIR, "--output", OSV_VULN_REPORT_PATH],
        outputPath: OSV_VULN_REPORT_PATH,
        format: "osv-json",
        successfulExitCodes: [0],
        defaultOutput: "{}",
        candidatesFromRecords: candidatesFromOsv,
      }),
  };
}

function actionlintStage(): StageDefinition {
  return {
    id: "scan.github-actions.actionlint",
    version: "1",
    dependencies: ["inventory.detect"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    timeoutMs: SCANNER_TIMEOUT_MS,
    run: (ctx) => {
      const { inventory } = readInput<InventoryData>(ctx, "inventory.detect");
      return runJsonScanner(ctx, {
        check: "github-actions.actionlint",
        tool: "actionlint",
        command: [
          "actionlint",
          "-format",
          "{{json .}}",
          "-shellcheck=",
          "-pyflakes=",
          ...inventory.workflows.map((workflow) => `${SOURCE_DIR}/${workflow}`),
        ],
        format: "actionlint-json",
        successfulExitCodes: [0, 1],
        defaultOutput: "[]",
        candidatesFromRecords: candidatesFromActionlint,
      });
    },
  };
}

function zizmorStage(): StageDefinition {
  return {
    id: "scan.github-actions.zizmor",
    version: "1",
    dependencies: ["inventory.detect"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    timeoutMs: SCANNER_TIMEOUT_MS,
    run: (ctx) =>
      runJsonScanner(ctx, {
        check: "github-actions.zizmor",
        tool: "zizmor",
        command: ["zizmor", "--offline", "--format=json", SOURCE_DIR],
        format: "zizmor-json-v1",
        successfulExitCodes: [0, 11, 12, 13, 14],
        defaultOutput: "[]",
        candidatesFromRecords: candidatesFromZizmor,
      }),
  };
}

function trivyConfigStage(): StageDefinition {
  return {
    id: "scan.iac.trivy-config",
    version: "1",
    dependencies: ["inventory.detect"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    timeoutMs: SCANNER_TIMEOUT_MS,
    run: (ctx) =>
      runJsonScanner(ctx, {
        check: "iac.trivy-config",
        tool: "trivy",
        command: [
          "trivy",
          "config",
          "--format",
          "json",
          "--output",
          TRIVY_CONFIG_REPORT_PATH,
          "--cache-dir",
          TRIVY_CACHE_DIR,
          SOURCE_DIR,
        ],
        outputPath: TRIVY_CONFIG_REPORT_PATH,
        format: "trivy-config-json",
        successfulExitCodes: [0],
        defaultOutput: "{}",
        candidatesFromRecords: candidatesFromTrivy,
      }),
  };
}

function normalizeStage(): StageDefinition {
  return {
    id: "findings.normalize",
    version: "1",
    dependencies: ["snapshot.manifest", ...SCANNER_STAGE_IDS],
    inputs: ["manifest", "scanner.raw"],
    outputs: [],
    required: true,
    run: async (ctx) => {
      const { manifest } = readInput<ManifestData>(ctx, "snapshot.manifest");
      const { rawArtifact, records } = readInput<GitleaksData>(ctx, "scan.secrets.gitleaks");
      const manifestFiles = new Set(manifest.files.map((file) => file.path));
      const evidence: Evidence[] = [];
      const findings: Finding[] = [];
      const seen = new Set<string>();

      for (const record of records) {
        const filePath = resolveManifestPath(
          normalizeScannerPath(record.File ?? ""),
          manifestFiles,
        );
        if (!manifestFiles.has(filePath)) {
          throw new Error(`gitleaks finding points outside the snapshot: ${filePath}`);
        }
        const startLine = positiveInt(record.StartLine, 1);
        const endLine = Math.max(startLine, positiveInt(record.EndLine, startLine));
        const snippet = redactedSnippet(record);
        const snippetHash = sha256Text(snippet);
        const ruleId = stringOr(record.RuleID, "gitleaks-secret");
        const evidenceId = stableId("ev", [
          "gitleaks",
          ruleId,
          filePath,
          String(startLine),
          snippetHash,
        ]);
        const fingerprint =
          typeof record.Fingerprint === "string" && record.Fingerprint.length > 0
            ? record.Fingerprint
            : stableId("fp", ["gitleaks", ruleId, filePath, String(startLine)]);
        if (seen.has(fingerprint)) {
          continue;
        }
        seen.add(fingerprint);
        evidence.push({
          id: evidenceId,
          rawArtifactBlobSha256: rawArtifact.blobSha256,
          filePath,
          startLine,
          endLine,
          snippet,
          snippetHash,
          tool: "gitleaks",
        });
        findings.push({
          id: stableId("finding", [fingerprint]),
          sourceTool: "gitleaks",
          ruleId,
          category: "secret",
          severity: "critical",
          confidence: "high",
          locations: [{ filePath, startLine, endLine }],
          evidenceIds: [evidenceId],
          fingerprint,
          remediationKey: "live-secret-in-source",
        });
      }

      for (const scanner of scannerRunsFromInputs(ctx)) {
        if (scanner.check === "secrets.gitleaks" || scanner.rawArtifact === undefined) {
          continue;
        }
        for (const candidate of scanner.candidates) {
          const rawFilePath = candidate.filePath;
          if (rawFilePath === undefined) {
            continue;
          }
          const filePath = resolveManifestPath(rawFilePath, manifestFiles);
          if (!manifestFiles.has(filePath)) {
            throw new Error(`${scanner.tool} finding points outside the snapshot: ${filePath}`);
          }
          const startLine = positiveInt(candidate.startLine, 1);
          const ruleId = candidate.ruleId ?? `${scanner.tool}-finding`;
          const message = candidate.message ?? `${scanner.tool} reported ${ruleId}`;
          const snippet = `${ruleId}: ${message}`;
          const snippetHash = sha256Text(snippet);
          const fingerprint = stableId("fp", [
            scanner.tool,
            ruleId,
            filePath,
            String(startLine),
            snippetHash,
          ]);
          if (seen.has(fingerprint)) {
            continue;
          }
          seen.add(fingerprint);
          const evidenceId = stableId("ev", [
            scanner.tool,
            ruleId,
            filePath,
            String(startLine),
            snippetHash,
          ]);
          const category = categoryForCheck(scanner.check);
          evidence.push({
            id: evidenceId,
            rawArtifactBlobSha256: scanner.rawArtifact.blobSha256,
            filePath,
            startLine,
            endLine: startLine,
            snippet,
            snippetHash,
            tool: scanner.tool,
          });
          findings.push({
            id: stableId("finding", [fingerprint]),
            sourceTool: scanner.tool,
            ruleId,
            category,
            severity: severityFromScanner(candidate.severity, category),
            confidence: "high",
            locations: [{ filePath, startLine, endLine: startLine }],
            evidenceIds: [evidenceId],
            fingerprint,
            ...(candidate.metadata === undefined ? {} : { metadata: candidate.metadata }),
            remediationKey: remediationKeyForCategory(category),
          });
        }
      }

      return success({ evidence, findings } satisfies NormalizeData);
    },
  };
}

function correlateStage(): StageDefinition {
  return {
    id: "findings.correlate",
    version: "1",
    dependencies: ["findings.normalize"],
    inputs: [],
    outputs: [],
    required: true,
    run: async (ctx) => {
      const { findings } = readInput<NormalizeData>(ctx, "findings.normalize");
      return success({ clusters: correlateFindings(findings) } satisfies CorrelateData);
    },
  };
}

function actionsStage(): StageDefinition {
  return {
    id: "actions.rank",
    version: "1",
    dependencies: [
      "snapshot.manifest",
      "findings.normalize",
      "findings.correlate",
      "inventory.detect",
      ...SCANNER_STAGE_IDS,
    ],
    inputs: [],
    outputs: [],
    required: true,
    run: async (ctx) => {
      const { evidence, findings } = readInput<NormalizeData>(ctx, "findings.normalize");
      const { scanPlan } = readInput<InventoryData>(ctx, "inventory.detect");
      const { manifest } = readInput<ManifestData>(ctx, "snapshot.manifest");
      const coverage = coverageFromScanPlan(
        scanPlan,
        scannerRunsFromInputs(ctx),
        manifest.toolchain,
      );
      const candidates = actionCandidatesFromFindings(findings, evidence);
      const verdict = verdictFor(findings, coverage);
      return success({ candidates, verdict } satisfies ActionsData);
    },
  };
}

function remediationStage(): StageDefinition {
  return {
    id: "remediation.generate",
    version: "1",
    dependencies: ["findings.normalize", "actions.rank"],
    inputs: [],
    outputs: [],
    required: true,
    run: async (ctx) => {
      const { evidence, findings } = readInput<NormalizeData>(ctx, "findings.normalize");
      const { candidates } = readInput<ActionsData>(ctx, "actions.rank");
      const catalogActions = candidates.map((candidate) => {
        const candidateFindings = findings.filter((finding) =>
          candidate.findingIds.includes(finding.id),
        );
        const candidateEvidence = evidence.filter((ev) => candidate.evidenceIds.includes(ev.id));
        return {
          candidate,
          remediation: catalogRemediation(candidate, candidateFindings, candidateEvidence),
        };
      });
      const rankedActions = await enhanceRemediations(ctx, catalogActions, findings, evidence);
      return success({ rankedActions } satisfies RemediationData);
    },
  };
}

interface ReportStageOptions {
  readonly deep: boolean;
}

function reportStage(options: ReportStageOptions): StageDefinition {
  return {
    id: "report.compose",
    version: "1",
    dependencies: [
      "snapshot.manifest",
      "inventory.detect",
      ...SCANNER_STAGE_IDS,
      "findings.normalize",
      "findings.correlate",
      "actions.rank",
      "remediation.generate",
      ...(options.deep ? [DEEP_STATIC_STAGE_ID, HYPOTHESIS_ENRICH_STAGE_ID] : []),
    ],
    inputs: [],
    outputs: ["report.json", "report.md", "report.html"],
    required: true,
    run: async (ctx) => {
      const { manifest } = readInput<ManifestData>(ctx, "snapshot.manifest");
      const { scanPlan } = readInput<InventoryData>(ctx, "inventory.detect");
      const coverage = coverageFromScanPlan(
        scanPlan,
        scannerRunsFromInputs(ctx),
        manifest.toolchain,
      );
      const { evidence, findings } = readInput<NormalizeData>(ctx, "findings.normalize");
      const { clusters } = readInput<CorrelateData>(ctx, "findings.correlate");
      const { verdict: quickVerdict } = readInput<ActionsData>(ctx, "actions.rank");
      const { rankedActions } = readInput<RemediationData>(ctx, "remediation.generate");
      const deepData = options.deep
        ? readInput<DeepStaticData>(ctx, DEEP_STATIC_STAGE_ID)
        : undefined;
      const enrichData = options.deep
        ? readInput<HypothesisEnrichData>(ctx, HYPOTHESIS_ENRICH_STAGE_ID)
        : undefined;
      const assessment = buildAssessment({
        repository: repositorySummary(ctx.source, manifest),
        manifest: summarizeManifest(manifest),
        toolchain: summarizeToolchain(manifest.toolchain),
        verdict: verdictWithDeepStatic(quickVerdict, deepData),
        coverage,
        findingSummary: summarizeFindings(findings),
        evidence,
        findings,
        findingClusters: clusters,
        rankedActions,
        ...(deepData === undefined
          ? {}
          : {
              deepCoverage: deepData.deepCoverage.entries,
              findingContextAssessments: deepData.findingContextAssessments,
              hypothesisCandidates: deepData.hypothesisCandidates,
              staticHypotheses: deepData.staticHypotheses,
              validationRecipes: deepData.validationRecipes,
              hypothesisEnrichments: enrichData?.hypothesisEnrichments ?? [],
              deepActionGroups: deepData.deepActionGroups,
              repositoryMapArtifactRef: deepData.repositoryMapArtifactRef,
              limitations: deepData.limitations,
            }),
        generatedAt: new Date().toISOString(),
      });

      await mkdir(ctx.runDir, { recursive: true });
      const json = jsonBytes(
        options.deep
          ? renderDeepReportJson(ctx.runId, assessment)
          : { runId: ctx.runId, assessment },
      );
      const markdown = encoder.encode(
        options.deep
          ? renderDeepMarkdownReport(ctx.runId, assessment)
          : renderMarkdown(ctx.runId, assessment),
      );
      const html = encoder.encode(
        options.deep
          ? renderDeepHtmlReport(ctx.runId, assessment)
          : renderHtml(ctx.runId, assessment),
      );

      await writeFile(path.join(ctx.runDir, "report.json"), json);
      await writeFile(path.join(ctx.runDir, "report.md"), markdown);
      await writeFile(path.join(ctx.runDir, "report.html"), html);

      const jsonBlob = await ctx.artifacts.store(json);
      const mdBlob = await ctx.artifacts.store(markdown);
      const htmlBlob = await ctx.artifacts.store(html);
      const reportArtifacts = [
        artifactRef(jsonBlob.sha256, "report.json", jsonBlob.bytes),
        artifactRef(mdBlob.sha256, "report.md", mdBlob.bytes),
        artifactRef(htmlBlob.sha256, "report.html", htmlBlob.bytes),
      ];

      return success(
        {
          assessment,
          reportArtifacts,
          reportPaths: {
            json: path.join(ctx.runDir, "report.json"),
            markdown: path.join(ctx.runDir, "report.md"),
            html: path.join(ctx.runDir, "report.html"),
            ...(deepData === undefined ? {} : { repositoryMap: deepData.repositoryMapPath }),
          },
        } satisfies ReportData,
        reportArtifacts,
      );
    },
  };
}

export function readReportData(
  data: ReadonlyMap<string, Readonly<Record<string, unknown>>>,
): ReportData {
  const value = data.get("report.compose");
  if (value === undefined) {
    throw new Error("report.compose did not produce data");
  }
  return value as unknown as ReportData;
}

function success(
  data: Readonly<Record<string, unknown>>,
  outputs: ArtifactRef[] = [],
): StageResult {
  return { status: "success", outputs, data };
}

function failed(error: string): StageResult {
  return { status: "failed", outputs: [], error };
}

function readInput<T>(ctx: StageContext, stageId: string): T {
  const data = ctx.inputs.get(stageId);
  if (data === undefined) {
    throw new Error(`Missing stage input: ${stageId}`);
  }
  return data as unknown as T;
}

async function execRequired(ctx: StageContext, command: string[], label: string): Promise<void> {
  const result = await ctx.session.exec(command);
  if (result.exitCode !== 0) {
    throw new Error(`${label} failed: ${formatExecFailure(result)}`);
  }
}

function formatExecFailure(result: ExecResult): string {
  const stderr = result.stderr.trim();
  const stdout = result.stdout.trim();
  return `exit ${result.exitCode}${stderr ? `; stderr: ${stderr}` : ""}${
    stdout ? `; stdout: ${stdout}` : ""
  }`;
}

function inventoryFromManifest(manifest: Manifest): RepositoryInventory {
  const languages = new Set<string>();
  const packageManifests: string[] = [];
  const workflows: string[] = [];
  const iacFiles: string[] = [];
  let codeFileCount = 0;

  for (const file of manifest.files) {
    const language = languageForPath(file.path);
    if (language !== null) {
      languages.add(language);
      codeFileCount += 1;
    }
    if (isPackageManifest(file.path)) {
      packageManifests.push(file.path);
    }
    if (isGithubActionsWorkflow(file.path)) {
      workflows.push(file.path);
    }
    if (isIacFile(file.path)) {
      iacFiles.push(file.path);
    }
  }

  return {
    languages: [...languages].sort(),
    packageManifests: packageManifests.sort(),
    workflows: workflows.sort(),
    iacFiles: iacFiles.sort(),
    codeFileCount,
  };
}

function scanPlanFromInventory(inventory: RepositoryInventory): ScanPlan {
  const hasCode = inventory.codeFileCount > 0;
  const hasPackageManifests = inventory.packageManifests.length > 0;
  const hasWorkflows = inventory.workflows.length > 0;
  const hasIac = inventory.iacFiles.length > 0;
  const checks: PlannedCheck[] = [
    {
      check: "secrets.gitleaks",
      tool: "gitleaks",
      applicable: true,
      required: true,
      implemented: true,
    },
    {
      check: "code-patterns.opengrep",
      tool: "opengrep",
      applicable: hasCode,
      required: true,
      implemented: true,
      ...(!hasCode ? { reason: "no supported source code files found" } : {}),
    },
    {
      check: "sbom.syft",
      tool: "syft",
      applicable: hasPackageManifests,
      required: true,
      implemented: true,
      ...(!hasPackageManifests ? { reason: "no dependency manifests found" } : {}),
    },
    {
      check: "dependencies.trivy",
      tool: "trivy",
      applicable: hasPackageManifests,
      required: true,
      implemented: true,
      ...(!hasPackageManifests ? { reason: "no dependency manifests found" } : {}),
    },
    {
      check: "dependencies.osv",
      tool: "osv",
      applicable: hasPackageManifests,
      required: true,
      implemented: true,
      ...(!hasPackageManifests ? { reason: "no dependency manifests found" } : {}),
    },
    {
      check: "github-actions.actionlint",
      tool: "actionlint",
      applicable: hasWorkflows,
      required: true,
      implemented: true,
      ...(!hasWorkflows ? { reason: "no GitHub Actions workflows found" } : {}),
    },
    {
      check: "github-actions.zizmor",
      tool: "zizmor",
      applicable: hasWorkflows,
      required: true,
      implemented: true,
      ...(!hasWorkflows ? { reason: "no GitHub Actions workflows found" } : {}),
    },
    {
      check: "iac.trivy-config",
      tool: "trivy",
      applicable: hasIac,
      required: true,
      implemented: true,
      ...(!hasIac ? { reason: "no IaC files found" } : {}),
    },
  ];
  return { checks };
}

function assertApplicableCheck(scanPlan: ScanPlan, checkId: string): void {
  const check = scanPlan.checks.find((planned) => planned.check === checkId);
  if (check === undefined) {
    throw new Error(`Scan plan is missing required check: ${checkId}`);
  }
  if (!check.applicable) {
    throw new Error(`Check ${checkId} is not applicable: ${check.reason ?? "no reason recorded"}`);
  }
}

interface JsonScannerOptions {
  readonly check: string;
  readonly tool: string;
  readonly command: string[];
  readonly format: string;
  readonly successfulExitCodes: ReadonlyArray<number>;
  readonly defaultOutput: string;
  readonly outputPath?: string;
  readonly candidatesFromRecords: (
    records: ReadonlyArray<unknown>,
    check: string,
    tool: string,
    inventory: RepositoryInventory,
  ) => ScannerCandidate[];
}

async function runJsonScanner(ctx: StageContext, opts: JsonScannerOptions): Promise<StageResult> {
  const { inventory, scanPlan } = readInput<InventoryData>(ctx, "inventory.detect");
  const planned = plannedCheck(scanPlan, opts.check);
  if (!planned.applicable) {
    return success({
      check: opts.check,
      tool: opts.tool,
      coverage: {
        check: opts.check,
        status: "skipped",
        reason: planned.reason ?? "not applicable to this snapshot",
      },
      recordCount: 0,
      candidates: [],
    } satisfies ScannerRunData);
  }

  let result: ExecResult;
  try {
    result = await ctx.session.exec(opts.command);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const redactedBytes = redactScannerBytes(jsonBytes({ error: message }));
    const stored = await ctx.artifacts.store(redactedBytes);
    const rawArtifact: RedactedRawArtifact = {
      blobSha256: stored.sha256,
      tool: opts.tool,
      format: opts.format,
      bytes: stored.bytes,
      redacted: true,
    };
    const artifact = artifactRef(stored.sha256, "scanner.raw", stored.bytes);
    return success(
      {
        check: opts.check,
        tool: opts.tool,
        coverage: {
          check: opts.check,
          status: "failed",
          reason: message,
        },
        rawArtifact,
        recordCount: 0,
        candidates: [],
      } satisfies ScannerRunData,
      [artifact],
    );
  }
  const acceptable = opts.successfulExitCodes.includes(result.exitCode);
  const rawBytes = await readScannerBytes(ctx, opts.outputPath, result, opts.defaultOutput);
  const redactedBytes = redactScannerBytes(rawBytes);
  const stored = await ctx.artifacts.store(redactedBytes);
  const rawArtifact: RedactedRawArtifact = {
    blobSha256: stored.sha256,
    tool: opts.tool,
    format: opts.format,
    bytes: stored.bytes,
    redacted: true,
  };
  const artifact = artifactRef(stored.sha256, "scanner.raw", stored.bytes);
  if (!acceptable) {
    return success(
      {
        check: opts.check,
        tool: opts.tool,
        coverage: {
          check: opts.check,
          status: "failed",
          reason: formatExecFailure(result),
        },
        rawArtifact,
        recordCount: 0,
        candidates: [],
      } satisfies ScannerRunData,
      [artifact],
    );
  }

  let records: unknown[];
  try {
    records = recordsFromJson(redactedBytes);
  } catch (error) {
    return success(
      {
        check: opts.check,
        tool: opts.tool,
        coverage: {
          check: opts.check,
          status: "failed",
          reason: errorMessage(error),
        },
        rawArtifact,
        recordCount: 0,
        candidates: [],
      } satisfies ScannerRunData,
      [artifact],
    );
  }
  return success(
    {
      check: opts.check,
      tool: opts.tool,
      coverage: { check: opts.check, status: "checked" },
      rawArtifact,
      recordCount: records.length,
      candidates: opts.candidatesFromRecords(records, opts.check, opts.tool, inventory),
    } satisfies ScannerRunData,
    [artifact],
  );
}

function plannedCheck(scanPlan: ScanPlan, checkId: string): PlannedCheck {
  const check = scanPlan.checks.find((planned) => planned.check === checkId);
  if (check === undefined) {
    throw new Error(`Scan plan is missing check: ${checkId}`);
  }
  return check;
}

function scannerRunsFromInputs(ctx: StageContext): ScannerRunData[] {
  return SCANNER_STAGE_IDS.map((stageId) => readScannerRun(ctx, stageId));
}

function readScannerRun(ctx: StageContext, stageId: ScannerStageId): ScannerRunData {
  if (stageId === "scan.secrets.gitleaks") {
    const data = readInput<GitleaksData>(ctx, stageId);
    return {
      check: data.check,
      tool: "gitleaks",
      coverage: data.coverage,
      rawArtifact: data.rawArtifact,
      recordCount: data.records.length,
      candidates: [],
    };
  }
  return readInput<ScannerRunData>(ctx, stageId);
}

async function readTrivyDbDate(ctx: StageContext): Promise<string | undefined> {
  try {
    const bytes = await ctx.session.read(`${TRIVY_CACHE_DIR}/db/metadata.json`);
    const parsed = parseJson<unknown>(bytes, "trivy db metadata");
    if (!isRecord(parsed)) {
      return undefined;
    }
    const raw =
      stringFrom(parsed.UpdatedAt) ??
      stringFrom(parsed.DownloadedAt) ??
      stringFrom(parsed.updatedAt) ??
      stringFrom(parsed.downloadedAt) ??
      stringFrom(parsed.updated_at) ??
      stringFrom(parsed.downloaded_at);
    return normalizeIsoTimestamp(raw);
  } catch {
    return undefined;
  }
}

function coverageFromScanPlan(
  scanPlan: ScanPlan,
  scannerRuns: ReadonlyArray<ScannerRunData>,
  toolchain: Manifest["toolchain"],
): CoverageEntry[] {
  const byCheck = new Map(scannerRuns.map((run) => [run.check, run.coverage]));
  const coverage: CoverageEntry[] = scanPlan.checks.map((check) => {
    const reported = byCheck.get(check.check);
    if (reported !== undefined) {
      return reported;
    }
    if (!check.applicable) {
      return {
        check: check.check,
        status: "skipped",
        reason: check.reason ?? "not applicable to this snapshot",
      };
    }
    return {
      check: check.check,
      status: check.implemented ? "failed" : "degraded",
      reason: check.implemented
        ? "applicable check did not complete"
        : "adapter not implemented yet",
    };
  });
  return degradeCoverageForStaleToolchain(coverage, toolchain);
}

function degradeCoverageForStaleToolchain(
  coverage: ReadonlyArray<CoverageEntry>,
  toolchain: Manifest["toolchain"],
): CoverageEntry[] {
  const staleTools = new Set(
    toolchain.tools.filter((tool) => tool.dbStale === true).map((tool) => tool.tool),
  );
  if (staleTools.size === 0) {
    return [...coverage];
  }
  return coverage.map((entry) => {
    if (entry.status !== "checked") {
      return entry;
    }
    const tool = toolForCheck(entry.check);
    if (tool === undefined || !staleTools.has(tool)) {
      return entry;
    }
    return {
      check: entry.check,
      status: "degraded",
      reason: `${tool} database freshness is stale; refresh failed before scan`,
    };
  });
}

function toolForCheck(check: string): string | undefined {
  if (check === "dependencies.trivy" || check === "iac.trivy-config") {
    return "trivy";
  }
  if (check === "secrets.gitleaks") {
    return "gitleaks";
  }
  if (check === "code-patterns.opengrep") {
    return "opengrep";
  }
  if (check === "sbom.syft") {
    return "syft";
  }
  if (check === "github-actions.actionlint") {
    return "actionlint";
  }
  if (check === "github-actions.zizmor") {
    return "zizmor";
  }
  return undefined;
}

function verdictFor(
  findings: ReadonlyArray<Finding>,
  coverage: ReadonlyArray<CoverageEntry>,
): Verdict {
  if (findings.some((finding) => finding.severity === "critical")) {
    return "critical-fix-needed";
  }
  if (findings.length > 0) {
    return "not-ready-to-deploy";
  }
  const lostRequiredCoverage = coverage.some(
    (entry) => entry.status === "failed" || entry.status === "degraded",
  );
  return lostRequiredCoverage ? "scan-incomplete" : "looks-ok-for-now";
}

function verdictWithDeepStatic(verdict: Verdict, deepData: DeepStaticData | undefined): Verdict {
  const hasSupportedAttackPath =
    deepData?.staticHypotheses.some((hypothesis) => hypothesis.status === "statically_supported") ??
    false;
  return hasSupportedAttackPath ? "not-ready-to-deploy" : verdict;
}

async function readScannerBytes(
  ctx: StageContext,
  outputPath: string | undefined,
  result: ExecResult,
  defaultOutput: string,
): Promise<Uint8Array> {
  if (outputPath !== undefined) {
    try {
      const fromFile = await ctx.session.read(outputPath);
      if (fromFile.byteLength > 0) {
        return fromFile;
      }
    } catch {
      // Some tools write JSON to stdout instead of their output file on errors.
    }
  }
  if (result.stdout.trim().length > 0) {
    return encoder.encode(result.stdout);
  }
  const stderr = result.stderr.trim();
  if (result.exitCode !== 0 && stderr.length > 0) {
    return jsonBytes({ stderr });
  }
  return encoder.encode(defaultOutput);
}

function recordsFromJson(bytes: Uint8Array): unknown[] {
  const text = decoder.decode(bytes).trim();
  if (text.length === 0) {
    return [];
  }
  const parsed = parseJsonValueWithRepair(text, "scanner JSON").value;
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (isRecord(parsed)) {
    const capitalResults = parsed.Results;
    if (Array.isArray(capitalResults)) {
      return capitalResults.flatMap((result) => {
        if (!isRecord(result)) {
          return [];
        }
        const target = stringFrom(result.Target);
        return [
          ...recordsWithTarget(result.Vulnerabilities, target),
          ...recordsWithTarget(result.Misconfigurations, target),
          ...recordsWithTarget(result.Secrets, target),
        ];
      });
    }
    const results = parsed.results;
    if (Array.isArray(results)) {
      return results;
    }
    const runs = parsed.runs;
    if (Array.isArray(runs)) {
      return runs.flatMap((run) =>
        isRecord(run) && Array.isArray(run.results) ? (run.results as unknown[]) : [],
      );
    }
    const vulnerabilities = parsed.Vulnerabilities;
    if (Array.isArray(vulnerabilities)) {
      return vulnerabilities;
    }
    const bomRefs = parsed.components;
    if (Array.isArray(bomRefs)) {
      return bomRefs;
    }
    return [];
  }
  throw new Error("scanner JSON root is not an array or object");
}

function recordsWithTarget(value: unknown, target: string | undefined): unknown[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) =>
    isRecord(item) && target !== undefined ? { ...item, Target: target } : item,
  );
}

function candidatesFromActionlint(
  records: ReadonlyArray<unknown>,
  check: string,
  tool: string,
  _inventory: RepositoryInventory,
): ScannerCandidate[] {
  return records.map((record) => {
    const item = isRecord(record) ? record : {};
    return scannerCandidate(check, tool, {
      ruleId: stringFrom(item.kind) ?? stringFrom(item.Kind),
      message: stringFrom(item.message) ?? stringFrom(item.Message),
      filePath: normalizeCandidatePath(stringFrom(item.filepath) ?? stringFrom(item.Filepath)),
      startLine: numberFrom(item.line) ?? numberFrom(item.Line),
    });
  });
}

function candidatesFromZizmor(
  records: ReadonlyArray<unknown>,
  check: string,
  tool: string,
  _inventory: RepositoryInventory,
): ScannerCandidate[] {
  return records.map((record) => {
    const item = isRecord(record) ? record : {};
    const determinations = isRecord(item.determinations) ? item.determinations : {};
    return scannerCandidate(check, tool, {
      ruleId: stringFrom(item.ident),
      message: stringFrom(item.desc),
      filePath: pathFromZizmorLocations(item.locations),
      startLine: lineFromZizmorLocations(item.locations),
      severity: stringFrom(determinations.severity),
    });
  });
}

function candidatesFromSarif(
  records: ReadonlyArray<unknown>,
  check: string,
  tool: string,
  _inventory: RepositoryInventory,
): ScannerCandidate[] {
  return records.map((record) => {
    const item = isRecord(record) ? record : {};
    const message = isRecord(item.message) ? item.message : {};
    const firstLocation = firstRecord(item.locations);
    const physicalLocation = isRecord(firstLocation?.physicalLocation)
      ? firstLocation.physicalLocation
      : {};
    const artifactLocation = isRecord(physicalLocation.artifactLocation)
      ? physicalLocation.artifactLocation
      : {};
    const region = isRecord(physicalLocation.region) ? physicalLocation.region : {};
    return scannerCandidate(check, tool, {
      ruleId: stringFrom(item.ruleId),
      message: stringFrom(message.text),
      filePath: normalizeCandidatePath(stringFrom(artifactLocation.uri)),
      startLine: numberFrom(region.startLine),
      severity: stringFrom(item.level),
    });
  });
}

function candidatesFromTrivy(
  records: ReadonlyArray<unknown>,
  check: string,
  tool: string,
  inventory: RepositoryInventory,
): ScannerCandidate[] {
  return records.map((record) => {
    const item = isRecord(record) ? record : {};
    const cause = isRecord(item.CauseMetadata) ? item.CauseMetadata : {};
    const normalizedPath =
      normalizeCandidatePath(stringFrom(cause.Resource)) ??
      normalizeCandidatePath(stringFrom(item.Target));
    return scannerCandidate(check, tool, {
      ruleId:
        stringFrom(item.VulnerabilityID) ??
        stringFrom(item.ID) ??
        stringFrom(item.AVDID) ??
        stringFrom(item.RuleID),
      message:
        stringFrom(item.Title) ??
        stringFrom(item.Message) ??
        stringFrom(item.Description) ??
        stringFrom(item.MisconfSummary),
      filePath:
        check === "dependencies.trivy"
          ? dependencyFindingPath(item, normalizedPath, inventory.packageManifests)
          : normalizedPath,
      startLine: numberFrom(cause.StartLine),
      severity: stringFrom(item.Severity),
      metadata: compactMetadata({
        packageName: stringFrom(item.PkgName),
        installedVersion: stringFrom(item.InstalledVersion),
        fixedVersion: stringFrom(item.FixedVersion),
      }),
    });
  });
}

function candidatesFromOsv(
  records: ReadonlyArray<unknown>,
  check: string,
  tool: string,
  _inventory: RepositoryInventory,
): ScannerCandidate[] {
  return records.flatMap((record) => {
    const item = isRecord(record) ? record : {};
    const packageName = stringFrom(item.packageName);
    const version = stringFrom(item.version);
    const filePath = normalizeCandidatePath(stringFrom(item.target));
    const vulns = Array.isArray(item.vulns) ? item.vulns : [];
    return vulns.map((vuln) => {
      const vulnRecord = isRecord(vuln) ? vuln : {};
      const id = stringFrom(vulnRecord.id) ?? "OSV";
      return scannerCandidate(check, tool, {
        ruleId: id,
        message:
          packageName === undefined || version === undefined
            ? `OSV reports ${id}`
            : `${packageName}@${version} is affected by ${id}`,
        filePath,
        severity: "medium",
        metadata: compactMetadata({
          packageName,
          installedVersion: version,
        }),
      });
    });
  });
}

function dependencyFindingPath(
  item: Readonly<Record<string, unknown>>,
  normalizedPath: string | undefined,
  packageManifests: ReadonlyArray<string>,
): string | undefined {
  if (normalizedPath !== undefined && packageManifests.includes(normalizedPath)) {
    return normalizedPath;
  }
  const purl = stringFrom(isRecord(item.PkgIdentifier) ? item.PkgIdentifier.PURL : undefined);
  const ecosystem = purl?.match(/^pkg:([^/]+)\//)?.[1]?.toLowerCase();
  if (ecosystem === "maven") {
    return firstManifest(packageManifests, ["pom.xml", "build.gradle", "build.gradle.kts"]);
  }
  if (ecosystem === "npm") {
    return firstManifest(packageManifests, [
      "package-lock.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "package.json",
    ]);
  }
  if (ecosystem === "golang") {
    return firstManifest(packageManifests, ["go.sum", "go.mod"]);
  }
  if (ecosystem === "pypi") {
    return firstManifest(packageManifests, [
      "requirements.txt",
      "poetry.lock",
      "Pipfile.lock",
      "pyproject.toml",
    ]);
  }
  return packageManifests[0];
}

function firstManifest(
  packageManifests: ReadonlyArray<string>,
  names: ReadonlyArray<string>,
): string | undefined {
  for (const name of names) {
    const exact = packageManifests.find((file) => file === name || file.endsWith(`/${name}`));
    if (exact !== undefined) {
      return exact;
    }
  }
  return undefined;
}

function scannerCandidate(
  check: string,
  tool: string,
  fields: ScannerCandidateFields,
): ScannerCandidate {
  return {
    check,
    tool,
    ...(fields.ruleId !== undefined ? { ruleId: fields.ruleId } : {}),
    ...(fields.message !== undefined ? { message: fields.message } : {}),
    ...(fields.filePath !== undefined ? { filePath: fields.filePath } : {}),
    ...(fields.startLine !== undefined ? { startLine: fields.startLine } : {}),
    ...(fields.severity !== undefined ? { severity: fields.severity } : {}),
    ...(fields.metadata === undefined ? {} : { metadata: fields.metadata }),
  };
}

function compactMetadata(
  values: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string>> | undefined {
  const entries = Object.entries(values).filter((entry): entry is [string, string] => {
    const value = entry[1];
    return typeof value === "string" && value.trim() !== "";
  });
  return entries.length === 0 ? undefined : Object.fromEntries(entries);
}

function pathFromZizmorLocations(value: unknown): string | undefined {
  const location = firstRecord(value);
  return normalizeCandidatePath(
    stringFrom(location?.path) ?? stringFrom(location?.file) ?? stringFrom(location?.filename),
  );
}

function lineFromZizmorLocations(value: unknown): number | undefined {
  const location = firstRecord(value);
  return (
    numberFrom(location?.line) ??
    numberFrom(location?.start_line) ??
    numberFrom(location?.startLine) ??
    numberFrom(location?.row)
  );
}

function firstRecord(value: unknown): Record<string, unknown> | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const first = value[0];
  return isRecord(first) ? first : undefined;
}

function normalizeCandidatePath(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  try {
    return normalizeScannerPath(value);
  } catch {
    return undefined;
  }
}

async function readReportBytes(ctx: StageContext, result: ExecResult): Promise<Uint8Array> {
  try {
    const fromFile = await ctx.session.read(GITLEAKS_REPORT_PATH);
    if (fromFile.byteLength > 0) {
      return fromFile;
    }
  } catch {
    // Some test doubles and tool versions return JSON on stdout instead.
  }
  if (result.stdout.trim().length > 0) {
    return encoder.encode(result.stdout);
  }
  return encoder.encode("[]");
}

function parseGitleaks(bytes: Uint8Array): GitleaksRecord[] {
  const text = decoder.decode(bytes).trim();
  if (text.length === 0) {
    return [];
  }
  const parsed = parseJsonValueWithRepair(text, "gitleaks JSON report").value;
  if (!Array.isArray(parsed)) {
    throw new Error("gitleaks JSON report is not an array");
  }
  return parsed as GitleaksRecord[];
}

function parseJson<T>(bytes: Uint8Array, label: string): T {
  try {
    return JSON.parse(decoder.decode(bytes)) as T;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not parse ${label}: ${message}`);
  }
}

interface ParsedJsonValue {
  readonly value: unknown;
  readonly repaired: boolean;
}

function parseJsonValueWithRepair(text: string, label: string): ParsedJsonValue {
  const body = text.trim();
  try {
    return { value: JSON.parse(body) as unknown, repaired: false };
  } catch (strictError) {
    const candidates = jsonRepairCandidates(body);
    const repairErrors: string[] = [];
    for (const candidate of candidates) {
      try {
        return { value: JSON.parse(candidate) as unknown, repaired: false };
      } catch {
        // Repair below handles common scanner/LLM JSON damage.
      }
      try {
        return { value: JSON.parse(jsonrepair(candidate)) as unknown, repaired: true };
      } catch (repairError) {
        repairErrors.push(errorMessage(repairError));
      }
    }
    throw new Error(
      `${label} was not valid JSON and could not be repaired: ${errorMessage(strictError)}; repair: ${
        repairErrors[0] ?? "no repair candidate"
      }`,
    );
  }
}

function jsonRepairCandidates(body: string): string[] {
  const candidates: string[] = [];
  candidates.push(...markdownFenceBodies(body));
  const firstJson = body.search(/[[{]/);
  const lastObject = body.lastIndexOf("}");
  const lastArray = body.lastIndexOf("]");
  const lastJson = Math.max(lastObject, lastArray);
  if (firstJson >= 0 && lastJson > firstJson) {
    candidates.push(body.slice(firstJson, lastJson + 1).trim());
  }
  candidates.push(body);
  return unique(candidates.filter((candidate) => candidate.length > 0));
}

function markdownFenceBodies(body: string): string[] {
  const matches = body.matchAll(/```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```/gi);
  return [...matches]
    .map((match) => match[1]?.trim())
    .filter((match): match is string => match !== undefined && match !== "");
}

interface RedactedGitleaksReport {
  readonly bytes: Uint8Array;
  readonly records: GitleaksRecord[];
  readonly error?: string;
}

function redactGitleaksReport(bytes: Uint8Array): RedactedGitleaksReport {
  try {
    const records = redactGitleaksRecords(parseGitleaks(bytes));
    return { bytes: jsonBytes(records), records };
  } catch (error) {
    return {
      bytes: redactScannerBytes(bytes),
      records: [],
      error: errorMessage(error),
    };
  }
}

function redactGitleaksRecords(records: ReadonlyArray<GitleaksRecord>): GitleaksRecord[] {
  return records.map((record) => {
    const out: Record<string, unknown> = { ...record };
    const secret = typeof record.Secret === "string" ? record.Secret : "";
    if (secret.length > 0) {
      out.Secret = "***REDACTED***";
    }
    if (typeof record.Match === "string") {
      out.Match =
        secret.length > 0 ? record.Match.split(secret).join("***REDACTED***") : "***REDACTED***";
    }
    return out as GitleaksRecord;
  });
}

function redactScannerBytes(bytes: Uint8Array): Uint8Array {
  return encoder.encode(redactSecrets(decoder.decode(bytes)));
}

function redactSecrets(text: string): string {
  return text
    .replace(
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
      "-----BEGIN REDACTED PRIVATE KEY-----\n***REDACTED***\n-----END REDACTED PRIVATE KEY-----",
    )
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "***REDACTED***")
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, "***REDACTED***")
    .replace(/\bsk_(?:live|test)_[A-Za-z0-9A-Za-z_=-]{10,}\b/g, "***REDACTED***")
    .replace(/\b(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1***REDACTED***")
    .replace(
      /\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd|pwd)\s*[:=]\s*["']?)[^"',\s\\]{8,}/gi,
      "$1***REDACTED***",
    );
}

function normalizeScannerPath(raw: string): string {
  let filePath = raw.trim();
  if (filePath.startsWith("file://")) {
    try {
      filePath = fileURLToPath(filePath);
    } catch {
      throw new Error(`Invalid scanner path: ${raw}`);
    }
  }
  if (filePath.startsWith(`${SOURCE_DIR}/`)) {
    filePath = filePath.slice(SOURCE_DIR.length + 1);
  }
  if (filePath.startsWith("./")) {
    filePath = filePath.slice(2);
  }
  if (
    filePath.length === 0 ||
    filePath.includes("\0") ||
    filePath.includes("\\") ||
    path.posix.isAbsolute(filePath) ||
    filePath.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error(`Invalid scanner path: ${raw}`);
  }
  return filePath;
}

function resolveManifestPath(filePath: string, manifestFiles: ReadonlySet<string>): string {
  if (manifestFiles.has(filePath)) {
    return filePath;
  }
  for (const variant of scannerPathVariants(filePath)) {
    if (manifestFiles.has(variant)) {
      return variant;
    }
  }
  return filePath;
}

function scannerPathVariants(filePath: string): string[] {
  const sourcePrefix = `${path.posix.basename(SOURCE_DIR)}/`;
  if (filePath.startsWith(sourcePrefix)) {
    return [filePath.slice(sourcePrefix.length)];
  }
  return [];
}

function redactedSnippet(record: GitleaksRecord): string {
  if (typeof record.Match === "string" && record.Match.length > 0) {
    return record.Match;
  }
  return `${stringOr(record.RuleID, "secret")} detected`;
}

async function enhanceRemediations(
  ctx: StageContext,
  catalogActions: ReadonlyArray<RankedAction>,
  findings: ReadonlyArray<Finding>,
  evidence: ReadonlyArray<Evidence>,
): Promise<RankedAction[]> {
  const available = await ctx.model.isAvailable().catch(() => false);
  if (!available || catalogActions.length === 0) {
    return [...catalogActions];
  }

  const modelActions = catalogActions.slice(0, MODEL_ACTION_LIMIT);
  const enhancedById = new Map<string, RemediationAction>();
  let completedModelActions = 0;
  emitModelProgress(
    ctx,
    "remediation.generate",
    "Writing fixes",
    completedModelActions,
    modelActions.length,
  );
  await mapWithConcurrency(modelActions, MODEL_REMEDIATION_CONCURRENCY, async (action) => {
    try {
      const enhanced = await ctx.model
        .enhance(modelEnhanceInput(ctx.source, [action], findings, evidence))
        .catch(() => null);
      if (enhanced === null) {
        return;
      }
      const validated = validateEnhancedRemediations(enhanced, [action]);
      const remediation = validated?.get(action.candidate.id);
      if (remediation !== undefined) {
        enhancedById.set(action.candidate.id, remediation);
      }
    } finally {
      completedModelActions += 1;
      emitModelProgress(
        ctx,
        "remediation.generate",
        "Writing fixes",
        completedModelActions,
        modelActions.length,
      );
    }
  });

  if (enhancedById.size === 0) {
    return [...catalogActions];
  }

  return catalogActions.map((ranked) => {
    const remediation = enhancedById.get(ranked.candidate.id);
    return remediation === undefined ? ranked : { candidate: ranked.candidate, remediation };
  });
}

function modelEnhanceInput(
  source: SourceInput,
  rankedActions: ReadonlyArray<RankedAction>,
  findings: ReadonlyArray<Finding>,
  evidence: ReadonlyArray<Evidence>,
): ModelEnhanceBatchInput {
  const findingsById = new Map(findings.map((finding) => [finding.id, finding]));
  const evidenceById = new Map(evidence.map((ev) => [ev.id, ev]));
  return {
    repositoryName:
      source.kind === "github" ? repoNameFromUrl(source.url) : path.basename(source.path),
    actions: rankedActions.map(({ candidate, remediation }) =>
      modelEnhanceActionInput(candidate, remediation, findingsById, evidenceById),
    ),
  };
}

function modelEnhanceActionInput(
  candidate: ActionCandidate,
  remediation: RemediationAction,
  findingsById: ReadonlyMap<string, Finding>,
  evidenceById: ReadonlyMap<string, Evidence>,
): ModelEnhanceActionInput {
  const candidateFindings = candidate.findingIds.flatMap((findingId) => {
    const finding = findingsById.get(findingId);
    return finding === undefined ? [] : [finding];
  });
  const modelFindings = sortModelFindings(candidateFindings)
    .flatMap((finding) => modelFindingInput(finding, evidenceById))
    .slice(0, MODEL_FINDING_LIMIT_PER_ACTION);
  const affectedFiles = candidate.affectedFiles.slice(0, MODEL_AFFECTED_FILE_LIMIT_PER_ACTION);

  return {
    candidateId: candidate.id,
    remediationKey: candidate.remediationKey,
    priorityScore: candidate.priorityScore,
    verdictImpact: candidate.verdictImpact,
    summary: {
      totalFindings: candidateFindings.length,
      includedFindings: modelFindings.length,
      omittedFindings: Math.max(0, candidateFindings.length - modelFindings.length),
      totalAffectedFiles: candidate.affectedFiles.length,
      includedAffectedFiles: affectedFiles.length,
      omittedAffectedFiles: Math.max(0, candidate.affectedFiles.length - affectedFiles.length),
      rules: topModelCounts(candidateFindings.map((finding) => finding.ruleId)),
      tools: topModelCounts(candidateFindings.map((finding) => finding.sourceTool)),
      severities: topModelCounts(candidateFindings.map((finding) => finding.severity)),
    },
    affectedFiles,
    catalogRemediation: remediation,
    findings: modelFindings,
  };
}

function modelFindingInput(
  finding: Finding,
  evidenceById: ReadonlyMap<string, Evidence>,
): ModelEnhanceActionInput["findings"][number][] {
  const location = finding.locations[0];
  if (location === undefined) {
    return [];
  }
  const snippet = finding.evidenceIds
    .map((evidenceId) => evidenceById.get(evidenceId)?.snippet)
    .find((value): value is string => value !== undefined);
  return [
    {
      findingId: finding.id,
      sourceTool: finding.sourceTool,
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      filePath: location.filePath,
      startLine: location.startLine,
      snippet: truncateForModel(redactSecrets(snippet ?? `${finding.ruleId} detected`)),
    },
  ];
}

function sortModelFindings(findings: ReadonlyArray<Finding>): Finding[] {
  return [...findings].sort((a, b) => {
    const severityDelta = severityRank(b.severity) - severityRank(a.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }
    return (
      a.sourceTool.localeCompare(b.sourceTool) ||
      a.ruleId.localeCompare(b.ruleId) ||
      (a.locations[0]?.filePath ?? "").localeCompare(b.locations[0]?.filePath ?? "") ||
      (a.locations[0]?.startLine ?? 0) - (b.locations[0]?.startLine ?? 0) ||
      a.id.localeCompare(b.id)
    );
  });
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    case "unknown":
      return 0;
  }
}

function topModelCounts(values: ReadonlyArray<string>): ModelEnhanceCount[] {
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, MODEL_SUMMARY_BUCKET_LIMIT);
}

async function mapWithConcurrency<T, R>(
  values: ReadonlyArray<T>,
  concurrency: number,
  mapper: (value: T) => Promise<R>,
): Promise<R[]> {
  const out: R[] = [];
  for (let index = 0; index < values.length; index += concurrency) {
    out.push(...(await Promise.all(values.slice(index, index + concurrency).map(mapper))));
  }
  return out;
}

function emitModelProgress(
  ctx: StageContext,
  stageId: StageId,
  label: string,
  completed: number,
  total: number,
): void {
  const publicLabel = `${label} ${completed}/${total}`;
  ctx.events.emit({
    type: "scan-progress",
    stageId,
    message: publicLabel,
    details: {
      publicLabel,
      source: "model",
      completed,
      total,
    },
    timestamp: new Date().toISOString(),
  });
}

function truncateForModel(value: string): string {
  if (value.length <= MODEL_SNIPPET_CHAR_LIMIT) {
    return value;
  }
  return `${value.slice(0, MODEL_SNIPPET_CHAR_LIMIT)}... [truncated]`;
}

function validateEnhancedRemediations(
  enhanced: ReadonlyArray<RemediationAction>,
  modelActions: ReadonlyArray<RankedAction>,
): Map<string, RemediationAction> | null {
  if (enhanced.length !== modelActions.length) {
    return null;
  }
  const expectedIds = new Set(modelActions.map((ranked) => ranked.candidate.id));
  const out = new Map<string, RemediationAction>();
  for (const remediation of enhanced) {
    if (!expectedIds.has(remediation.candidateId) || out.has(remediation.candidateId)) {
      return null;
    }
    const ranked = modelActions.find((action) => action.candidate.id === remediation.candidateId);
    if (ranked === undefined) {
      return null;
    }
    const sanitized = sanitizeModelRemediation(remediation);
    if (!remediationTextAvoidsUnsafePaths(sanitized)) {
      return null;
    }
    out.set(remediation.candidateId, sanitized);
  }
  return out;
}

function sanitizeModelRemediation(remediation: RemediationAction): RemediationAction {
  return {
    candidateId: remediation.candidateId,
    title: redactSecrets(remediation.title),
    risk: redactSecrets(remediation.risk),
    whyFixNow: redactSecrets(remediation.whyFixNow),
    fixSteps: remediation.fixSteps.map(redactSecrets),
    operationalSteps: remediation.operationalSteps.map(redactSecrets),
    agentPrompt: redactSecrets(remediation.agentPrompt),
    verifySteps: remediation.verifySteps.map(redactSecrets),
    fromCatalog: false,
  };
}

function remediationTextAvoidsUnsafePaths(remediation: RemediationAction): boolean {
  const text = [
    remediation.title,
    remediation.risk,
    remediation.whyFixNow,
    remediation.agentPrompt,
    ...remediation.fixSteps,
    ...remediation.operationalSteps,
    ...remediation.verifySteps,
  ].join("\n");
  if (/(^|[\s"'`(])(?:\/(?:tmp|work|Users|home|root|etc|var)\b|[A-Za-z]:\\|\.\.)/.test(text)) {
    return false;
  }
  return true;
}

function catalogRemediation(
  candidate: ActionCandidate,
  findings: ReadonlyArray<Finding>,
  evidence: ReadonlyArray<Evidence>,
): RemediationAction {
  const firstEvidence = evidence.find((ev) => candidate.evidenceIds.includes(ev.id));
  const location =
    firstEvidence !== undefined
      ? `${firstEvidence.filePath}:${firstEvidence.startLine}`
      : (candidate.affectedFiles[0] ?? "the repository");
  const ruleIds = unique(findings.map((finding) => finding.ruleId)).join(", ");
  if (candidate.remediationKey !== "live-secret-in-source") {
    return genericCatalogRemediation(candidate, location, ruleIds);
  }
  return {
    candidateId: candidate.id,
    title: "Remove the committed secret",
    risk: "A secret-looking credential is present in source code. Anyone with repository access or a leaked copy could reuse it.",
    whyFixNow: "Shipping with a live-looking key in the repo can expose accounts or services.",
    fixSteps: [
      `Remove the secret from ${location}.`,
      "Load the value from runtime configuration or a secret manager instead of source code.",
      "Add a safe example value for local setup.",
    ],
    operationalSteps: [
      "Rotate or revoke the exposed credential in the provider console.",
      "Check recent provider logs for unexpected use.",
    ],
    agentPrompt: [
      `There is a secret-looking credential committed in source code at ${location} (detected rule: ${ruleIds}).`,
      "Replace it with environment-based configuration: remove the committed value, load it from an environment variable or secret manager, add a safe placeholder for local setup, and update or add tests so the app still starts without a committed secret.",
      "Do not print, log, or keep the secret value anywhere in code, tests, comments, or docs.",
    ].join("\n"),
    verifySteps: [
      "Run the app's tests or typecheck.",
      "Run VibeShield again and confirm the gitleaks finding is gone.",
    ],
    fromCatalog: true,
  };
}

function genericCatalogRemediation(
  candidate: ActionCandidate,
  location: string,
  ruleIds: string,
): RemediationAction {
  const template = genericRemediationTemplate(candidate.remediationKey);
  return {
    candidateId: candidate.id,
    title: template.title,
    risk: template.risk,
    whyFixNow: template.whyFixNow,
    fixSteps: template.fixSteps(location),
    operationalSteps: template.operationalSteps,
    agentPrompt: [
      `${template.title} at ${location} (detected rule: ${ruleIds}).`,
      template.agentInstruction,
      "Keep the change minimal, preserve existing behavior where possible, and add a focused check that the fix works.",
    ].join("\n"),
    verifySteps: template.verifySteps,
    fromCatalog: true,
  };
}

function genericRemediationTemplate(remediationKey: string) {
  switch (remediationKey) {
    case "dependency-vulnerability":
      return {
        title: "Review the vulnerable dependency",
        risk: "A dependency scanner reported a vulnerable package or dependency manifest.",
        whyFixNow:
          "Known vulnerable dependencies can be reachable even when the application code looks unchanged.",
        fixSteps: (location: string) => [
          `Review the dependency finding at ${location}.`,
          "Upgrade, replace, or remove the affected package using the smallest compatible change.",
          "Update the lockfile together with the manifest when applicable.",
        ],
        operationalSteps: ["Check whether the vulnerable package is used in a deployed path."],
        agentInstruction:
          "Inspect the dependency manifest or lockfile, apply the smallest safe upgrade/removal, and explain any compatibility risk.",
        verifySteps: ["Run the package manager install/check command.", "Run VibeShield again."],
      };
    case "github-actions-hardening":
      return {
        title: "Harden the GitHub Actions workflow",
        risk: "A workflow scanner reported a CI/CD configuration issue that can weaken repository or deployment security.",
        whyFixNow:
          "Workflow issues can expose secrets, broaden token permissions, or run untrusted input during automation.",
        fixSteps: (location: string) => [
          `Review the workflow finding at ${location}.`,
          "Apply the least-privilege workflow change recommended by the scanner.",
          "Keep workflow behavior equivalent unless the insecure behavior is the problem.",
        ],
        operationalSteps: [
          "Review recent workflow runs if the finding involves secret or token exposure.",
        ],
        agentInstruction:
          "Patch the workflow YAML with least privilege and safe expression handling; do not broaden permissions to silence the scanner.",
        verifySteps: ["Run actionlint or the workflow parser locally.", "Run VibeShield again."],
      };
    case "iac-hardening":
      return {
        title: "Fix the infrastructure configuration issue",
        risk: "An IaC scanner reported a configuration that may expose infrastructure or weaken runtime isolation.",
        whyFixNow:
          "Infrastructure defaults are easy to ship accidentally and can become externally reachable after deploy.",
        fixSteps: (location: string) => [
          `Review the IaC finding at ${location}.`,
          "Tighten the configuration using the scanner rule as the source of truth.",
          "Keep environment-specific values configurable instead of hard-coding exceptions.",
        ],
        operationalSteps: [
          "Confirm the deployed environment is not already using the unsafe setting.",
        ],
        agentInstruction:
          "Patch the IaC file to satisfy the reported rule while preserving the intended deployment shape.",
        verifySteps: [
          "Run the IaC validation or plan command if available.",
          "Run VibeShield again.",
        ],
      };
    default:
      return {
        title: "Review the static analysis finding",
        risk: "A code scanner reported a pattern that can become a security issue.",
        whyFixNow:
          "Static findings are cheapest to fix before the app is shipped or copied further.",
        fixSteps: (location: string) => [
          `Review the scanner finding at ${location}.`,
          "Replace the risky pattern with a boring, explicit implementation.",
          "Add a regression test when the behavior is security-sensitive.",
        ],
        operationalSteps: [],
        agentInstruction:
          "Refactor the reported code pattern into a safer equivalent and keep the diff narrow.",
        verifySteps: ["Run the relevant test or typecheck.", "Run VibeShield again."],
      };
  }
}

function repositorySummary(source: SourceInput, manifest: Manifest) {
  const base = {
    name: source.kind === "github" ? repoNameFromUrl(source.url) : path.basename(source.path),
    ...(manifest.commitSha !== null ? { commitSha: manifest.commitSha } : {}),
  };
  if (source.kind === "github") {
    return { ...base, originUrl: source.url };
  }
  const localOriginUrl =
    source.originUrl ?? (manifest.origin.kind === "local" ? manifest.origin.originUrl : undefined);
  return {
    ...base,
    ...(localOriginUrl === undefined ? {} : { originUrl: localOriginUrl }),
    localPath: source.path,
  };
}

function summarizeFindings(findings: ReadonlyArray<Finding>) {
  const bySeverity: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
    byCategory[finding.category] = (byCategory[finding.category] ?? 0) + 1;
  }
  return { total: findings.length, bySeverity, byCategory };
}

function correlateFindings(findings: ReadonlyArray<Finding>): FindingCluster[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const firstFile = finding.locations[0]?.filePath ?? "repository";
    const key = [finding.category, finding.remediationKey ?? finding.ruleId, firstFile].join("\0");
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }
  return [...groups.entries()].map(([key, group]) => ({
    id: stableId("cluster", [key]),
    category: group[0]?.category ?? "code-pattern",
    findingIds: group.map((finding) => finding.id),
    maxSeverity: maxSeverity(group.map((finding) => finding.severity)),
  }));
}

function actionCandidatesFromFindings(
  findings: ReadonlyArray<Finding>,
  evidence: ReadonlyArray<Evidence>,
): ActionCandidate[] {
  const evidenceById = new Map(evidence.map((ev) => [ev.id, ev]));
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = finding.remediationKey ?? remediationKeyForCategory(finding.category);
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }
  return [...groups.entries()]
    .map(([remediationKey, group]) => {
      const groupEvidence = unique(
        group.flatMap((finding) => finding.evidenceIds).filter((id) => evidenceById.has(id)),
      );
      const severity = maxSeverity(group.map((finding) => finding.severity));
      return {
        id: stableId("action", group.map((finding) => finding.fingerprint).sort()),
        remediationKey,
        priorityScore: priorityScoreFor(severity, group[0]?.category ?? "code-pattern"),
        findingIds: group.map((finding) => finding.id),
        evidenceIds: groupEvidence,
        affectedFiles: unique(group.flatMap((f) => f.locations.map((loc) => loc.filePath))),
        verdictImpact: verdictImpactFor(severity),
      } satisfies ActionCandidate;
    })
    .sort(
      (a, b) =>
        b.priorityScore - a.priorityScore || a.remediationKey.localeCompare(b.remediationKey),
    );
}

function categoryForCheck(check: string): FindingCategory {
  if (check.startsWith("code-patterns.")) {
    return "code-pattern";
  }
  if (check.startsWith("dependencies.")) {
    return "dependency";
  }
  if (check.startsWith("github-actions.")) {
    return "github-action";
  }
  if (check.startsWith("iac.")) {
    return "iac";
  }
  if (check.startsWith("sbom.")) {
    return "sbom";
  }
  return "code-pattern";
}

function remediationKeyForCategory(category: FindingCategory): string {
  switch (category) {
    case "secret":
      return "live-secret-in-source";
    case "dependency":
      return "dependency-vulnerability";
    case "github-action":
      return "github-actions-hardening";
    case "iac":
      return "iac-hardening";
    case "sbom":
      return "sbom-inventory-review";
    case "code-pattern":
      return "code-pattern-review";
  }
}

function severityFromScanner(value: string | undefined, category: FindingCategory): Severity {
  const normalized = value?.toLowerCase();
  if (normalized === "critical") {
    return "critical";
  }
  if (normalized === "high" || normalized === "error") {
    return "high";
  }
  if (normalized === "medium" || normalized === "warning") {
    return "medium";
  }
  if (normalized === "low" || normalized === "note") {
    return "low";
  }
  return category === "github-action" || category === "iac" ? "medium" : "unknown";
}

function maxSeverity(values: ReadonlyArray<Severity>): Severity {
  const order: Severity[] = ["unknown", "low", "medium", "high", "critical"];
  return values.reduce<Severity>(
    (max, value) => (order.indexOf(value) > order.indexOf(max) ? value : max),
    "unknown",
  );
}

function priorityScoreFor(severity: Severity, category: FindingCategory): number {
  const base = {
    critical: 100,
    high: 80,
    medium: 50,
    low: 20,
    unknown: 10,
  } satisfies Record<Severity, number>;
  const categoryBoost = category === "secret" ? 10 : category === "dependency" ? 5 : 0;
  return base[severity] + categoryBoost;
}

function verdictImpactFor(severity: Severity): ActionCandidate["verdictImpact"] {
  if (severity === "critical" || severity === "high") {
    return "blocks-deploy";
  }
  if (severity === "medium") {
    return "degrades";
  }
  return "informational";
}

function languageForPath(filePath: string): string | null {
  const ext = path.posix.extname(filePath).toLowerCase();
  switch (ext) {
    case ".ts":
    case ".tsx":
      return "typescript";
    case ".js":
    case ".jsx":
    case ".mjs":
    case ".cjs":
      return "javascript";
    case ".py":
      return "python";
    case ".go":
      return "go";
    case ".rs":
      return "rust";
    case ".java":
      return "java";
    case ".kt":
    case ".kts":
      return "kotlin";
    case ".cs":
      return "csharp";
    case ".php":
      return "php";
    case ".rb":
      return "ruby";
    case ".swift":
      return "swift";
    case ".c":
    case ".h":
      return "c";
    case ".cc":
    case ".cpp":
    case ".cxx":
    case ".hpp":
    case ".hh":
      return "cpp";
    case ".vue":
      return "vue";
    case ".svelte":
      return "svelte";
    default:
      return null;
  }
}

function isPackageManifest(filePath: string): boolean {
  const base = path.posix.basename(filePath);
  if (
    [
      "package.json",
      "package-lock.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "bun.lock",
      "bun.lockb",
      "requirements.txt",
      "pyproject.toml",
      "poetry.lock",
      "Pipfile",
      "Pipfile.lock",
      "setup.py",
      "setup.cfg",
      "go.mod",
      "go.sum",
      "Cargo.toml",
      "Cargo.lock",
      "pom.xml",
      "composer.json",
      "composer.lock",
      "Gemfile",
      "Gemfile.lock",
      "mix.exs",
      "mix.lock",
      "pubspec.yaml",
      "pubspec.lock",
      "Package.swift",
    ].includes(base)
  ) {
    return true;
  }
  return (
    /^requirements[-\w]*\.txt$/i.test(base) ||
    /^build\.gradle(\.kts)?$/i.test(base) ||
    /\.csproj$/i.test(base)
  );
}

function isGithubActionsWorkflow(filePath: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(filePath);
}

function isIacFile(filePath: string): boolean {
  if (isGithubActionsWorkflow(filePath)) {
    return false;
  }
  const base = path.posix.basename(filePath);
  const lowerPath = filePath.toLowerCase();
  if (/^dockerfile([.-].*)?$/i.test(base)) {
    return true;
  }
  if (/^(docker-)?compose([.-].*)?\.ya?ml$/i.test(base)) {
    return true;
  }
  if (/\.(tf|tfvars)$/i.test(base)) {
    return true;
  }
  if (base === "Chart.yaml" || /^values([.-].*)?\.ya?ml$/i.test(base)) {
    return lowerPath.includes("/helm/") || lowerPath.includes("/charts/");
  }
  return (
    /\.(ya?ml|json)$/i.test(base) &&
    (lowerPath.startsWith("k8s/") ||
      lowerPath.startsWith("kubernetes/") ||
      lowerPath.includes("/k8s/") ||
      lowerPath.includes("/kubernetes/"))
  );
}

function renderMarkdown(_runId: string, assessment: ReturnType<typeof buildAssessment>): string {
  const actions = assessment.rankedActions;
  const lines = [
    `# VibeShield — ${repositoryName(assessment)}`,
    "",
    `**Verdict:** ${verdictLabel(assessment.verdict)}`,
    "",
    verdictSubline(assessment),
    "",
    `${actions.length} ${actions.length === 1 ? "fix" : "fixes"} to make · ${assessment.manifest.fileCount} files scanned`,
    "",
    `> ${assessment.limitation}`,
    "",
    "## Fix these first",
    "",
    actions.length > 0
      ? "Each problem below comes with a prompt you can paste straight into your coding agent. Work through them in order."
      : "No blocking fixes were produced by the checks that completed.",
    "",
  ];
  actions.forEach((ranked, index) => {
    const { remediation } = ranked;
    lines.push(`### ${index + 1}. ${remediation.title}`, "");
    lines.push(remediation.risk, "");
    lines.push(`**Why now:** ${remediation.whyFixNow}`, "");
    lines.push("**Prompt for your coding agent**", "");
    lines.push("Copy this whole block into your coding agent:");
    lines.push("", "```text", remediation.agentPrompt, "```", "");
    appendMarkdownList(
      lines,
      "You'll need to do this yourself (your agent can't)",
      remediation.operationalSteps,
    );
    lines.push(`**Where:** ${markdownList(actionLocationsForReport(ranked, assessment))}`, "");
    appendMarkdownList(lines, "Or change it by hand", remediation.fixSteps);
    appendMarkdownList(lines, "Check it worked", remediation.verifySteps);
  });
  lines.push("## What was checked", "", "| Check | Status | Notes |", "| --- | --- | --- |");
  for (const entry of assessment.coverage) {
    lines.push(
      `| ${coverageCheckLabel(entry.check)} | ${coverageStatusLabel(entry.status)} | ${entry.reason ?? ""} |`,
    );
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function renderHtml(_runId: string, assessment: ReturnType<typeof buildAssessment>): string {
  const actions = assessment.rankedActions;
  const sections = [
    verdictBannerHtml(assessment),
    statsHtml([
      {
        value: String(actions.length),
        label: actions.length === 1 ? "fix to make" : "fixes to make",
      },
      { value: String(assessment.manifest.fileCount), label: "files scanned" },
    ]),
    noteHtml(assessment.limitation),
    sectionHeadingHtml(
      "Fix these first",
      actions.length > 0
        ? "Each problem below comes with a prompt you can paste straight into your coding agent. Work through them in order."
        : "No blocking fixes were produced by the checks that completed.",
    ),
    ...actions.map((ranked, index) => actionCardHtml(index + 1, ranked, assessment)),
    coverageDetailsHtml("What was checked", assessment.coverage.map(coverageRowFromQuickCheck)),
  ];
  return renderReportDocument({
    repoName: repositoryName(assessment),
    brandSub: "Quick Scan",
    sections,
    footerMeta: footerMetaLine(assessment),
  });
}

function appendMarkdownList(lines: string[], heading: string, values: ReadonlyArray<string>): void {
  if (values.length === 0) {
    return;
  }
  lines.push(`**${heading}**`, "");
  for (const value of values) {
    lines.push(`- ${value}`);
  }
  lines.push("");
}

function markdownList(values: ReadonlyArray<string>): string {
  return values.length > 0 ? values.join(", ") : "Repository";
}

function opengrepRules(): string {
  return [
    "rules:",
    "  - id: javascript-eval",
    "    languages: [javascript, typescript]",
    "    message: Avoid eval on application-controlled data.",
    "    severity: ERROR",
    "    pattern: eval($VALUE)",
    "  - id: javascript-function-constructor",
    "    languages: [javascript, typescript]",
    "    message: Avoid constructing executable code from strings.",
    "    severity: WARNING",
    "    pattern: new Function(...)",
    "",
  ].join("\n");
}

function sarifEmptyReport(): string {
  return JSON.stringify({ version: "2.1.0", runs: [{ results: [] }] });
}

function manifestScript(): string {
  return String.raw`
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const sourceDir = process.argv[2];
const originPath = process.argv[3];
const filterPath = process.argv[4];
const outPath = process.argv[5];
const imageTag = process.argv[6] ?? "vibeshield-toolchain:latest";
const toolchainFreshnessPath = process.argv[7];

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

const origin = JSON.parse(await readFile(originPath, "utf8"));
const filter = await readOptionalJson(filterPath);
const toolchainFreshness = await readOptionalJson(toolchainFreshnessPath);
const freshnessByTool = new Map();
for (const item of Array.isArray(toolchainFreshness?.tools) ? toolchainFreshness.tools : []) {
  if (item && typeof item.tool === "string") {
    freshnessByTool.set(item.tool, {
      dbDate: typeof item.dbDate === "string" ? item.dbDate : undefined,
      dbStale: item.dbStale === true,
    });
  }
}
const exclusions = [...(filter?.exclusions ?? [])];
const preFiltered = filter?.mode === "pre-filtered";

let commitSha = null;
let files;
if (preFiltered) {
  commitSha = typeof filter?.commitSha === "string" ? filter.commitSha : null;
  files = await walkFiles(sourceDir, false, exclusions);
} else if (await exists(path.join(sourceDir, ".git"))) {
  commitSha = git(["-C", sourceDir, "rev-parse", "HEAD"]);
  const rels = git(["-C", sourceDir, "ls-files", "-c", "-o", "--exclude-standard", "-z"])
    .split("\0")
    .filter(Boolean)
    .map(toPosixPath)
    .filter(isSafeRelativePath);
  for (const ignored of git(["-C", sourceDir, "ls-files", "-o", "-i", "--exclude-standard", "--directory", "-z"])
    .split("\0")
    .filter(Boolean)
    .map(toPosixPath)
    .map(normalizeGitIgnoredPath)
    .filter(isSafeRelativePath)) {
    if (!rels.includes(ignored) && !hasIncludedChild(rels, ignored)) {
      exclusions.push({ path: ignored, reason: "git-ignored" });
    }
  }
  exclusions.push({ path: ".git", reason: "builtin-ignore" });
  files = await filesFromList(sourceDir, rels, exclusions);
} else {
  files = await walkFiles(sourceDir, true, exclusions);
}

const sourceHash = createHash("sha256");
for (const file of files) {
  sourceHash.update(file.path);
  sourceHash.update("\0");
  sourceHash.update(file.sha256);
  sourceHash.update("\0");
  sourceHash.update(String(file.size));
  sourceHash.update("\n");
}

const manifest = {
  origin,
  commitSha,
  sourceHash: sourceHash.digest("hex"),
  files,
  exclusions,
  toolchain: {
    imageTag,
    tools: [
      toolRecord("gitleaks", ["version"]),
      toolRecord("opengrep", ["--version"]),
      toolRecord("syft", ["version"]),
      toolRecord("trivy", ["--version"]),
      toolRecord("actionlint", ["-version"]),
      toolRecord("zizmor", ["--version"]),
    ],
  },
  createdAt: new Date().toISOString(),
};

await writeFile(outPath, JSON.stringify(manifest, null, 2));

async function walkFiles(root, applyBuiltin, exclusions) {
  const rels = [];
  async function walk(absDir, relDir) {
    const entries = await readdir(absDir, { withFileTypes: true });
    for (const entry of entries) {
      const rel = toPosixPath(path.join(relDir, entry.name));
      if (!isSafeRelativePath(rel)) continue;
      const abs = path.join(root, rel);
      if (entry.isDirectory()) {
        if (applyBuiltin && BUILTIN_IGNORED_DIRS.has(entry.name)) {
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
      if (entry.isFile()) rels.push(rel);
    }
  }
  await walk(root, "");
  return filesFromList(root, rels, exclusions);
}

async function filesFromList(root, rels, exclusions) {
  const files = [];
  let totalBytes = 0;
  for (const rel of [...new Set(rels)].sort()) {
    const st = await lstat(path.join(root, rel));
    if (st.isSymbolicLink()) {
      exclusions.push({ path: rel, reason: "symlink-escape" });
      continue;
    }
    if (!st.isFile()) continue;
    if (st.size > MAX_FILE_BYTES) {
      exclusions.push({ path: rel, reason: "too_large" });
      continue;
    }
    if (files.length >= MAX_FILES || totalBytes + st.size > MAX_TOTAL_BYTES) {
      exclusions.push({ path: rel, reason: "truncated" });
      continue;
    }
    const bytes = await readFile(path.join(root, rel));
    files.push({ path: rel, size: st.size, sha256: createHash("sha256").update(bytes).digest("hex") });
    totalBytes += st.size;
  }
  return files;
}

async function exists(p) {
  try {
    await lstat(p);
    return true;
  } catch {
    return false;
  }
}

async function readOptionalJson(p) {
  if (typeof p !== "string" || p.length === 0) {
    return null;
  }
  try {
    return JSON.parse(await readFile(p, "utf8"));
  } catch {
    return null;
  }
}

function git(args) {
  return execFileSync("git", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).trim();
}

function toolVersion(bin, args) {
  try {
    return normalizeToolVersion(execFileSync(bin, args, { encoding: "utf8" }));
  } catch {
    return "unknown";
  }
}

function toolRecord(bin, args) {
  const freshness = freshnessByTool.get(bin);
  const out = { tool: bin, version: toolVersion(bin, args) };
  if (freshness?.dbDate) out.dbDate = freshness.dbDate;
  if (freshness?.dbStale !== undefined) out.dbStale = freshness.dbStale;
  return out;
}

function normalizeToolVersion(output) {
  const lines = output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const line = lines.find((candidate) => /\b\d+\.\d+(?:\.\d+)?/.test(candidate)) ?? lines[0] ?? "unknown";
  const match = line.match(/\bv?(\d+\.\d+(?:\.\d+)?(?:[-+][^\s]+)?)\b/);
  return match?.[1] ?? line;
}

function toPosixPath(p) {
  return p.split(path.sep).join("/");
}

function isSafeRelativePath(rel) {
  return (
    rel.length > 0 &&
    !rel.includes("\0") &&
    !rel.includes("\\") &&
    !path.posix.isAbsolute(rel) &&
    rel.split("/").every((part) => part !== "" && part !== "." && part !== "..")
  );
}

function normalizeGitIgnoredPath(rel) {
  return rel.replace(/\/+$/u, "");
}

function hasIncludedChild(files, rel) {
  const prefix = rel + "/";
  return files.some((file) => file.startsWith(prefix));
}
`;
}

function artifactRef(blobSha256: string, role: ArtifactRef["role"], bytes: number): ArtifactRef {
  return { blobSha256, role, bytes };
}

function jsonBytes(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value, null, 2));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function positiveInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;
}

function numberFrom(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringFrom(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function normalizeIsoTimestamp(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) {
    return value;
  }
  return parsed.toISOString();
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sha256Text(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

function stableId(prefix: string, parts: ReadonlyArray<string>): string {
  return `${prefix}_${sha256Text(parts.join("\0")).slice(0, 16)}`;
}

function unique(values: ReadonlyArray<string>): string[] {
  return [...new Set(values)];
}

function repoNameFromUrl(url: string): string {
  const clean = url.replace(/\.git$/, "");
  return clean.split("/").filter(Boolean).at(-1) ?? clean;
}
