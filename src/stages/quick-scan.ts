import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { ActionCandidate, RemediationAction } from "../domain/action.js";
import { type Verdict, verdictLabel } from "../domain/assessment.js";
import type { Evidence, RedactedRawArtifact } from "../domain/evidence.js";
import type { Finding } from "../domain/finding.js";
import type { Manifest } from "../domain/manifest.js";
import { summarizeManifest, summarizeToolchain } from "../domain/manifest-summary.js";
import type { ArtifactRef, SourceInput } from "../domain/run.js";
import { buildAssessment, type RankedAction } from "../domain/security-assessment.js";
import type { StageContext, StageDefinition, StageResult } from "../pipeline/stage-definition.js";
import type { ExecResult } from "../ports/sandbox-runtime.js";
import { createLocalSourcePackage } from "./local-source-package.js";
import {
  GITLEAKS_REPORT_PATH,
  LOCAL_SOURCE_TAR,
  MANIFEST_PATH,
  MANIFEST_SCRIPT_PATH,
  ORIGIN_PATH,
  SOURCE_DIR,
  SOURCE_FILTER_PATH,
  WORK_DIR,
} from "./paths.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function quickScanStages(): StageDefinition[] {
  return [
    sourceResolveStage(),
    snapshotManifestStage(),
    gitleaksStage(),
    normalizeStage(),
    actionsStage(),
    remediationStage(),
    reportStage(),
  ];
}

interface SourceResolveData {
  readonly sourceDir: string;
}

interface ManifestData {
  readonly manifest: Manifest;
  readonly manifestArtifact: ArtifactRef;
}

interface GitleaksData {
  readonly rawArtifact: RedactedRawArtifact;
  readonly records: GitleaksRecord[];
}

interface NormalizeData {
  readonly evidence: Evidence[];
  readonly findings: Finding[];
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
    run: async (ctx) => {
      await execRequired(ctx, ["node", "--version"], "toolchain preflight: node");
      await execRequired(ctx, ["git", "--version"], "toolchain preflight: git");
      await execRequired(ctx, ["gitleaks", "version"], "toolchain preflight: gitleaks");
      await execRequired(ctx, ["mkdir", "-p", WORK_DIR], "create work directory");
      await execRequired(ctx, ["rm", "-rf", SOURCE_DIR], "clear previous source directory");
      await ctx.session.uploadBytes(ORIGIN_PATH, jsonBytes(ctx.source));

      if (ctx.source.kind === "github") {
        await execRequired(
          ctx,
          ["git", "clone", "--depth", "1", ctx.source.url, SOURCE_DIR],
          "clone GitHub repository",
        );
      } else {
        const pkg = await createLocalSourcePackage(ctx.source.path);
        try {
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

function snapshotManifestStage(): StageDefinition {
  return {
    id: "snapshot.manifest",
    version: "1",
    dependencies: ["source.resolve"],
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

function gitleaksStage(): StageDefinition {
  return {
    id: "scan.secrets.gitleaks",
    version: "1",
    dependencies: ["snapshot.manifest"],
    inputs: [],
    outputs: ["scanner.raw"],
    required: true,
    run: async (ctx) => {
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
      const parsed = parseGitleaks(rawBytes);
      const redactedRecords = redactGitleaksRecords(parsed);
      const redactedBytes = jsonBytes(redactedRecords);
      const stored = await ctx.artifacts.store(redactedBytes);
      const rawArtifact: RedactedRawArtifact = {
        blobSha256: stored.sha256,
        tool: "gitleaks",
        format: "gitleaks-json",
        bytes: stored.bytes,
        redacted: true,
      };
      const artifact = artifactRef(stored.sha256, "scanner.raw", stored.bytes);
      return success({ rawArtifact, records: redactedRecords } satisfies GitleaksData, [artifact]);
    },
  };
}

function normalizeStage(): StageDefinition {
  return {
    id: "findings.normalize",
    version: "1",
    dependencies: ["snapshot.manifest", "scan.secrets.gitleaks"],
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
        const filePath = normalizeScannerPath(record.File ?? "");
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

      return success({ evidence, findings } satisfies NormalizeData);
    },
  };
}

function actionsStage(): StageDefinition {
  return {
    id: "actions.rank",
    version: "1",
    dependencies: ["findings.normalize"],
    inputs: [],
    outputs: [],
    required: true,
    run: async (ctx) => {
      const { evidence, findings } = readInput<NormalizeData>(ctx, "findings.normalize");
      const candidates: ActionCandidate[] = [];
      if (findings.length > 0) {
        candidates.push({
          id: stableId("action", findings.map((f) => f.fingerprint).sort()),
          remediationKey: "live-secret-in-source",
          priorityScore: 100,
          findingIds: findings.map((f) => f.id),
          evidenceIds: evidence.map((ev) => ev.id),
          affectedFiles: unique(findings.flatMap((f) => f.locations.map((loc) => loc.filePath))),
          verdictImpact: "blocks-deploy",
        });
      }
      const verdict: Verdict = findings.length > 0 ? "critical-fix-needed" : "looks-ok-for-now";
      return success({ candidates, verdict } satisfies ActionsData);
    },
  };
}

function remediationStage(): StageDefinition {
  return {
    id: "remediation.catalog",
    version: "1",
    dependencies: ["findings.normalize", "actions.rank"],
    inputs: [],
    outputs: [],
    required: true,
    run: async (ctx) => {
      const { evidence, findings } = readInput<NormalizeData>(ctx, "findings.normalize");
      const { candidates } = readInput<ActionsData>(ctx, "actions.rank");
      const rankedActions = candidates.map((candidate) => ({
        candidate,
        remediation: catalogRemediation(candidate, findings, evidence),
      }));
      return success({ rankedActions } satisfies RemediationData);
    },
  };
}

function reportStage(): StageDefinition {
  return {
    id: "report.compose",
    version: "1",
    dependencies: [
      "snapshot.manifest",
      "findings.normalize",
      "actions.rank",
      "remediation.catalog",
    ],
    inputs: [],
    outputs: ["report.json", "report.md", "report.html"],
    required: true,
    run: async (ctx) => {
      const { manifest } = readInput<ManifestData>(ctx, "snapshot.manifest");
      const { evidence, findings } = readInput<NormalizeData>(ctx, "findings.normalize");
      const { verdict } = readInput<ActionsData>(ctx, "actions.rank");
      const { rankedActions } = readInput<RemediationData>(ctx, "remediation.catalog");
      const assessment = buildAssessment({
        repository: repositorySummary(ctx.source, manifest),
        manifest: summarizeManifest(manifest),
        toolchain: summarizeToolchain(manifest.toolchain),
        verdict,
        coverage: [{ check: "secrets.gitleaks", status: "checked" }],
        findingSummary: summarizeFindings(findings),
        evidence,
        findings,
        rankedActions,
        generatedAt: new Date().toISOString(),
      });

      await mkdir(ctx.runDir, { recursive: true });
      const json = jsonBytes({ runId: ctx.runId, assessment });
      const markdown = encoder.encode(renderMarkdown(ctx.runId, assessment));
      const html = encoder.encode(renderHtml(ctx.runId, assessment));

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
  const parsed = JSON.parse(text) as unknown;
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

function normalizeScannerPath(raw: string): string {
  let filePath = raw.trim();
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

function redactedSnippet(record: GitleaksRecord): string {
  if (typeof record.Match === "string" && record.Match.length > 0) {
    return record.Match;
  }
  return `${stringOr(record.RuleID, "secret")} detected`;
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
      "Fix this VibeShield finding without printing or preserving the secret value.",
      `Location: ${location}`,
      `Rule: ${ruleIds}`,
      "Replace the committed credential with environment-based configuration, update any example config safely, and add or adjust tests so the app still starts without a committed secret.",
      "Do not add the secret value to logs, tests, docs, or comments.",
    ].join("\n"),
    verifySteps: [
      "Run the app's tests or typecheck.",
      "Run VibeShield again and confirm the gitleaks finding is gone.",
    ],
    fromCatalog: true,
  };
}

function repositorySummary(source: SourceInput, manifest: Manifest) {
  const base = {
    name: source.kind === "github" ? repoNameFromUrl(source.url) : path.basename(source.path),
    ...(manifest.commitSha !== null ? { commitSha: manifest.commitSha } : {}),
  };
  if (source.kind === "github") {
    return { ...base, originUrl: source.url };
  }
  return { ...base, localPath: source.path };
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

function renderMarkdown(runId: string, assessment: ReturnType<typeof buildAssessment>): string {
  const lines = [
    "# VibeShield Quick Scan",
    "",
    `Run: ${runId}`,
    `Verdict: ${verdictLabel(assessment.verdict)}`,
    `Files scanned: ${assessment.manifest.fileCount}`,
    `Findings: ${assessment.findingSummary.total}`,
    "",
    assessment.limitation,
    "",
  ];
  for (const ranked of assessment.rankedActions) {
    lines.push(`## ${ranked.remediation.title}`, "", ranked.remediation.risk, "");
    lines.push("```text", ranked.remediation.agentPrompt, "```", "");
  }
  return `${lines.join("\n")}\n`;
}

function renderHtml(runId: string, assessment: ReturnType<typeof buildAssessment>): string {
  const actions = assessment.rankedActions
    .map(
      (ranked) =>
        `<section><h2>${escapeHtml(ranked.remediation.title)}</h2><p>${escapeHtml(
          ranked.remediation.risk,
        )}</p><pre>${escapeHtml(ranked.remediation.agentPrompt)}</pre></section>`,
    )
    .join("");
  return [
    "<!doctype html>",
    '<html lang="en">',
    '<head><meta charset="utf-8"><title>VibeShield Quick Scan</title></head>',
    "<body>",
    "<h1>VibeShield Quick Scan</h1>",
    `<p>Run: ${escapeHtml(runId)}</p>`,
    `<p>Verdict: ${escapeHtml(verdictLabel(assessment.verdict))}</p>`,
    `<p>Files scanned: ${assessment.manifest.fileCount}</p>`,
    `<p>Findings: ${assessment.findingSummary.total}</p>`,
    `<p>${escapeHtml(assessment.limitation)}</p>`,
    actions,
    "</body></html>",
  ].join("");
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
  for (const ignored of git(["-C", sourceDir, "ls-files", "-o", "-i", "--exclude-standard", "-z"])
    .split("\0")
    .filter(Boolean)
    .map(toPosixPath)
    .filter(isSafeRelativePath)) {
    exclusions.push({ path: ignored, reason: "git-ignored" });
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
    imageTag: process.env.VIBESHIELD_TOOLCHAIN_TAG ?? "vibeshield-toolchain:latest",
    tools: [{ tool: "gitleaks", version: gitleaksVersion() }],
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
  try {
    return JSON.parse(await readFile(p, "utf8"));
  } catch {
    return null;
  }
}

function git(args) {
  return execFileSync("git", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).trim();
}

function gitleaksVersion() {
  try {
    return execFileSync("gitleaks", ["version"], { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
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
`;
}

function artifactRef(blobSha256: string, role: ArtifactRef["role"], bytes: number): ArtifactRef {
  return { blobSha256, role, bytes };
}

function jsonBytes(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value, null, 2));
}

function positiveInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
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

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
