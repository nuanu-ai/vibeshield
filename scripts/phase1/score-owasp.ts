#!/usr/bin/env tsx
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

type Tool = "codeql" | "joern" | "semgrep" | "vibeshield";
type Language = "java" | "python";

interface Options {
  readonly role: "held-out" | "tuning";
  readonly language: Language;
  readonly truth: string;
  readonly out: string;
  readonly cwes: ReadonlyArray<number>;
  readonly tools: ReadonlyArray<Tool>;
  readonly runs: Readonly<Partial<Record<Tool, string>>>;
}

interface TruthCase {
  readonly id: string;
  readonly cwe: number;
  readonly vulnerable: boolean;
}

interface Detection {
  readonly tool: Tool;
  readonly cwe: number;
  readonly testId: string;
  readonly path: string;
  readonly line?: number;
  readonly ruleId: string;
  readonly blocking: boolean;
}

interface NormalizedOutput {
  readonly detections: ReadonlyArray<Detection>;
  readonly coverageLoss: ReadonlyArray<unknown>;
}

interface Ratio {
  readonly numerator: number;
  readonly denominator: number;
  readonly value: number | null;
}

export async function scoreOwasp(options: Options): Promise<Record<string, unknown>> {
  const truth = await readTruth(options.truth);
  const manifests = await Promise.all(
    options.tools.map(async (tool) => {
      const run = required(options.runs[tool]);
      return [tool, await readJson(path.join(run, "run-manifest.json"))] as const;
    }),
  );
  assertComparableRuns(manifests, options.language);
  const outputsByTool = new Map<Tool, NormalizedOutput>();
  for (const tool of options.tools) {
    outputsByTool.set(tool, await normalize(tool, required(options.runs[tool])));
  }

  const cells = options.tools.flatMap((tool) =>
    options.cwes.map((cwe) =>
      scoreCell(
        tool,
        options.language,
        cwe,
        truth,
        outputsByTool.get(tool)?.detections ?? [],
        outputsByTool.get(tool)?.coverageLoss ?? [],
      ),
    ),
  );
  const aggregates = options.tools.map((tool) => {
    const selected = cells.filter((cell) => cell.tool === tool && cell.eligible);
    return aggregate(tool, selected);
  });
  const vibeCells = cells.filter((cell) => cell.tool === "vibeshield");
  const baselineTools: ReadonlyArray<Tool> = ["codeql", "semgrep", "joern"];
  const comparative = options.cwes.map((cwe) => {
    const vibe = vibeCells.find((cell) => cell.cwe === cwe);
    const baselineCells = cells.filter(
      (cell) => cell.cwe === cwe && baselineTools.includes(cell.tool) && cell.eligible,
    );
    const bestBaselineF05 = Math.max(...baselineCells.map((cell) => cell.f05.value ?? 0), 0);
    return {
      cwe,
      eligible: vibe?.eligible === true && baselineCells.length === baselineTools.length,
      vibeShieldF05: vibe?.f05.value ?? null,
      bestBaselineF05,
      passed: vibe?.eligible === true && (vibe.f05.value ?? -1) >= bestBaselineF05,
    };
  });
  const eligibleTruthCases = truth.filter((item) => options.cwes.includes(item.cwe)).length;
  const vibeAggregate = aggregates.find((item) => item.tool === "vibeshield");
  const baselineAggregateF05 = Math.max(
    ...aggregates
      .filter((item) => baselineTools.includes(item.tool))
      .map((item) => item.f05.value ?? 0),
    0,
  );
  const allToolsPresent = tools.every((tool) => options.tools.includes(tool));
  const heldOutGate = {
    applicable: options.role === "held-out" && allToolsPresent,
    denominator: {
      eligibleCells: vibeCells.filter((cell) => cell.eligible).length,
      selectedCases: eligibleTruthCases,
      passed: vibeCells.filter((cell) => cell.eligible).length >= 3 && eligibleTruthCases >= 100,
    },
    perCellPrecision:
      vibeCells.length === options.cwes.length &&
      vibeCells.every(
        (cell) => cell.eligible && cell.precision.value !== null && cell.precision.value >= 0.9,
      ),
    perCellRecall:
      vibeCells.length === options.cwes.length &&
      vibeCells.every(
        (cell) => cell.eligible && cell.recall.value !== null && cell.recall.value >= 0.8,
      ),
    aggregatePrecision:
      vibeAggregate?.eligible === true &&
      vibeAggregate.precision.value !== null &&
      vibeAggregate.precision.value >= 0.9,
    aggregateRecall:
      vibeAggregate?.eligible === true &&
      vibeAggregate.recall.value !== null &&
      vibeAggregate.recall.value >= 0.8,
    zeroFalseBlockers:
      vibeCells.reduce(
        (sum, cell) => sum + (typeof cell.falseBlockers === "number" ? cell.falseBlockers : 0),
        0,
      ) === 0,
    f05NoWorsePerCell: comparative.every((item) => item.eligible && item.passed),
    f05NoWorseAggregate:
      vibeAggregate?.eligible === true && (vibeAggregate.f05.value ?? -1) >= baselineAggregateF05,
  };
  const accepted =
    options.role === "held-out" &&
    allToolsPresent &&
    Object.entries(heldOutGate)
      .filter(([key]) => key !== "applicable" && key !== "denominator")
      .every(([, value]) => value === true) &&
    heldOutGate.denominator.passed;

  const output = {
    schemaVersion: 1,
    role: options.role,
    language: options.language,
    tools: options.tools,
    target: comparableTarget(manifests),
    truthCases: truth.length,
    selectedCwes: options.cwes,
    denominatorPolicy: { minimumCases: 20, minimumVulnerable: 10, minimumClean: 10 },
    resultIdentity: "tool plus CWE plus OWASP test id; no report grouping or semantic hardcode",
    cells,
    aggregates,
    comparative,
    heldOutGate,
    accepted,
  };
  await writeFile(options.out, `${JSON.stringify(output, null, 2)}\n`);
  return output;
}

function scoreCell(
  tool: Tool,
  language: Language,
  cwe: number,
  truth: ReadonlyArray<TruthCase>,
  raw: ReadonlyArray<Detection>,
  coverageLoss: ReadonlyArray<unknown>,
) {
  const positives = new Set(
    truth.filter((item) => item.cwe === cwe && item.vulnerable).map((item) => item.id),
  );
  const clean = new Set(
    truth.filter((item) => item.cwe === cwe && !item.vulnerable).map((item) => item.id),
  );
  const allTruthIds = new Set(truth.map((item) => item.id));
  const detections = deduplicate(raw.filter((item) => item.cwe === cwe));
  const detectedIds = new Set(detections.map((item) => item.testId));
  const tp = [...detectedIds].filter((id) => positives.has(id)).length;
  const fp = [...detectedIds].filter((id) => allTruthIds.has(id) && !positives.has(id)).length;
  const fn = [...positives].filter((id) => !detectedIds.has(id)).length;
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const eligible = positives.size + clean.size >= 20 && positives.size >= 10 && clean.size >= 10;
  const falseBlockers = detections.filter((item) => item.blocking && clean.has(item.testId)).length;
  return {
    tool,
    language,
    cwe,
    denominator: {
      cases: positives.size + clean.size,
      vulnerable: positives.size,
      clean: clean.size,
    },
    eligible,
    status: eligible ? "scoreable" : "insufficient_denominator",
    tp,
    fp,
    fn,
    precision,
    recall,
    f05: f05(precision, recall),
    falseBlockers: tool === "vibeshield" ? falseBlockers : "not_applicable",
    coverageLoss,
    detectionCount: detections.length,
  };
}

function aggregate(tool: Tool, cells: ReadonlyArray<ReturnType<typeof scoreCell>>) {
  const tp = cells.reduce((sum, cell) => sum + cell.tp, 0);
  const fp = cells.reduce((sum, cell) => sum + cell.fp, 0);
  const fn = cells.reduce((sum, cell) => sum + cell.fn, 0);
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  return {
    tool,
    eligible: cells.length >= 3,
    cells: cells.length,
    tp,
    fp,
    fn,
    precision,
    recall,
    f05: f05(precision, recall),
  };
}

async function normalize(tool: Tool, run: string): Promise<NormalizedOutput> {
  switch (tool) {
    case "codeql": {
      const sarif = await readJson(path.join(run, "results.sarif"));
      return { detections: normalizeSarif(tool, sarif), coverageLoss: sarifCoverageLoss(sarif) };
    }
    case "semgrep": {
      const result = await readJson(path.join(run, "results.json"));
      return {
        detections: normalizeSemgrep(result),
        coverageLoss: semgrepCoverageLoss(result),
      };
    }
    case "joern":
      return {
        detections: normalizeJoern(await readFile(path.join(run, "results.tsv"), "utf8")),
        coverageLoss: [],
      };
    case "vibeshield": {
      const report = await readVibeShieldReport(run);
      return {
        detections: normalizeVibeShield(report),
        coverageLoss: vibeShieldCoverageLoss(report),
      };
    }
  }
}

function sarifCoverageLoss(input: unknown): unknown[] {
  const root = record(input);
  return array(root?.runs).flatMap((rawRun) => {
    const run = record(rawRun);
    return array(run?.invocations).flatMap((rawInvocation) => {
      const invocation = record(rawInvocation);
      const executionSuccessful = invocation?.executionSuccessful;
      const notifications = array(invocation?.toolExecutionNotifications).flatMap(
        (rawNotification) => {
          const notification = record(rawNotification);
          if (notification?.level !== "error") return [];
          return [{ reason: "tool_execution_error", notification }];
        },
      );
      return executionSuccessful === false
        ? [{ reason: "tool_execution_unsuccessful" }, ...notifications]
        : notifications;
    });
  });
}

function semgrepCoverageLoss(input: unknown): unknown[] {
  const root = record(input);
  return array(root?.errors).map((error) => ({ reason: "semgrep_error", error }));
}

function vibeShieldCoverageLoss(input: unknown): unknown[] {
  const assessment = record(record(input)?.assessment);
  const quickLoss = array(assessment?.coverage).flatMap((rawCoverage) => {
    const item = record(rawCoverage);
    if (item === undefined || item.status === "checked") return [];
    return [
      {
        reason: "vibeshield_coverage_not_checked",
        area: item.check,
        state: item.status,
        detail: item.reason,
      },
    ];
  });
  const deepLoss = array(assessment?.deepCoverage).flatMap((rawCoverage) => {
    const item = record(rawCoverage);
    if (item === undefined || item.state === "checked") return [];
    return [
      {
        reason: "vibeshield_deep_coverage_not_checked",
        area: item.area,
        state: item.state,
        coveredCount: item.coveredCount,
        totalCount: item.totalCount,
        detail: item.reason,
      },
    ];
  });
  return [...quickLoss, ...deepLoss];
}

function normalizeSarif(tool: Tool, input: unknown): Detection[] {
  const root = record(input);
  const runs = array(root?.runs);
  return runs.flatMap((rawRun) => {
    const run = record(rawRun);
    const driver = record(record(run?.tool)?.driver);
    const ruleCwes = new Map<string, number[]>();
    for (const rawRule of array(driver?.rules)) {
      const rule = record(rawRule);
      const id = string(rule?.id);
      if (id !== undefined) {
        ruleCwes.set(id, extractCwes(rule));
      }
    }
    return array(run?.results).flatMap((rawResult) => {
      const result = record(rawResult);
      if (result === undefined) return [];
      const ruleId = string(result?.ruleId);
      if (ruleId === undefined) return [];
      const location = firstLocation(result);
      if (location === undefined) return [];
      const testId = owaspTestId(location.path);
      if (testId === undefined) return [];
      return (ruleCwes.get(ruleId) ?? extractCwes(result)).map((cwe) => ({
        tool,
        cwe,
        testId,
        path: location.path,
        ...(location.line === undefined ? {} : { line: location.line }),
        ruleId,
        blocking: false,
      }));
    });
  });
}

function normalizeSemgrep(input: unknown): Detection[] {
  const root = record(input);
  return array(root?.results).flatMap((rawResult) => {
    const result = record(rawResult);
    const resultPath = string(result?.path);
    const ruleId = string(result?.check_id);
    const extra = record(result?.extra);
    const testId = resultPath === undefined ? undefined : owaspTestId(resultPath);
    if (resultPath === undefined || ruleId === undefined || testId === undefined) return [];
    const startLine = number(record(result?.start)?.line);
    return extractCwes(record(extra?.metadata)).map((cwe) => ({
      tool: "semgrep" as const,
      cwe,
      testId,
      path: resultPath,
      ...(startLine === undefined ? {} : { line: startLine }),
      ruleId,
      blocking: false,
    }));
  });
}

function normalizeJoern(input: string): Detection[] {
  return input
    .split(/\r?\n/u)
    .slice(1)
    .filter(Boolean)
    .flatMap((line) => {
      const fields = line.split("\t");
      const cwe = Number(fields[0]);
      const sinkFile = decode(fields[2]);
      const sourceFile = decode(fields[5]);
      // Interprocedural paths can terminate in a shared helper. The case identity then
      // comes from the source endpoint, while the reported finding stays at the sink.
      const testId = owaspTestId(sinkFile) ?? owaspTestId(sourceFile);
      if (!Number.isInteger(cwe) || testId === undefined) return [];
      const lineNumber = Number(fields[3]);
      return [
        {
          tool: "joern" as const,
          cwe,
          testId,
          path: sinkFile,
          ...(Number.isInteger(lineNumber) ? { line: lineNumber } : {}),
          ruleId: `direct-joern-cwe-${cwe}`,
          blocking: false,
        },
      ];
    });
}

function normalizeVibeShield(input: unknown): Detection[] {
  const assessment = record(record(input)?.assessment);
  return array(assessment?.findings).flatMap((rawFinding) => {
    const finding = record(rawFinding);
    const ruleId = string(finding?.ruleId);
    const severity = string(finding?.severity);
    const cwes = extractCwes({ ruleId });
    if (ruleId === undefined || cwes.length === 0) return [];
    return array(finding?.locations).flatMap((rawLocation) => {
      const location = record(rawLocation);
      const file = string(location?.filePath);
      const testId = file === undefined ? undefined : owaspTestId(file);
      if (file === undefined || testId === undefined) return [];
      const startLine = number(location?.startLine);
      return cwes.map((cwe) => ({
        tool: "vibeshield" as const,
        cwe,
        testId,
        path: file,
        ...(startLine === undefined ? {} : { line: startLine }),
        ruleId,
        blocking: severity === "critical" || severity === "high",
      }));
    });
  });
}

async function readVibeShieldReport(run: string): Promise<unknown> {
  const runsRoot = path.join(run, "state/runs");
  const directories = (await readdir(runsRoot)).sort();
  if (directories.length !== 1) {
    throw new Error(`expected exactly one VibeShield run in ${runsRoot}`);
  }
  return await readJson(path.join(runsRoot, required(directories[0]), "report.json"));
}

async function readTruth(file: string): Promise<TruthCase[]> {
  const lines = (await readFile(file, "utf8")).split(/\r?\n/u).filter(Boolean).slice(1);
  return lines.map((line) => {
    const [id, , vulnerable, cweRaw] = line.split(",").map((item) => item.trim());
    const cwe = Number(cweRaw);
    if (id === undefined || !/^BenchmarkTest\d+$/u.test(id) || !Number.isInteger(cwe)) {
      throw new Error(`invalid OWASP truth row: ${line}`);
    }
    return { id, cwe, vulnerable: vulnerable?.toLowerCase() === "true" };
  });
}

function assertComparableRuns(
  manifests: ReadonlyArray<readonly [Tool, unknown]>,
  language: Language,
): void {
  const commits = new Set<string>();
  for (const [tool, raw] of manifests) {
    const manifest = record(raw);
    if (manifest?.state !== "complete") throw new Error(`${tool} run is not complete`);
    if (manifest?.language !== language) throw new Error(`${tool} language mismatch`);
    const target = record(manifest?.target);
    const commit = string(target?.commit);
    if (commit === undefined) throw new Error(`${tool} target commit is missing`);
    commits.add(commit);
  }
  if (commits.size !== 1) throw new Error("tool runs do not use the same target commit");
}

function comparableTarget(manifests: ReadonlyArray<readonly [Tool, unknown]>) {
  const first = record(manifests[0]?.[1]);
  return first?.target;
}

function extractCwes(value: unknown): number[] {
  const matches = JSON.stringify(value).matchAll(/cwe(?:[-_/ ]|%2f)*(?:cwe[-_/ ]*)?0*(\d{1,4})/giu);
  return [...new Set([...matches].map((match) => Number(match[1])).filter(Number.isInteger))].sort(
    (left, right) => left - right,
  );
}

function firstLocation(
  result: Record<string, unknown>,
): { path: string; line?: number } | undefined {
  const location = record(array(result.locations)[0]);
  const physical = record(location?.physicalLocation);
  const artifact = record(physical?.artifactLocation);
  const region = record(physical?.region);
  const resultPath = string(artifact?.uri);
  if (resultPath === undefined) return undefined;
  const line = number(region?.startLine);
  return { path: resultPath, ...(line === undefined ? {} : { line }) };
}

function deduplicate(values: ReadonlyArray<Detection>): Detection[] {
  const seen = new Set<string>();
  return values.filter((item) => {
    const key = `${item.tool}:${item.cwe}:${item.testId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function owaspTestId(value: string): string | undefined {
  return value.match(/BenchmarkTest\d+/u)?.[0];
}

function ratio(numerator: number, denominator: number): Ratio {
  return {
    numerator,
    denominator,
    value: denominator === 0 ? null : round(numerator / denominator),
  };
}

function f05(precision: Ratio, recall: Ratio): { readonly value: number | null } {
  if (precision.value === null || recall.value === null) return { value: null };
  const denominator = 0.25 * precision.value + recall.value;
  return {
    value: denominator === 0 ? 0 : round((1.25 * precision.value * recall.value) / denominator),
  };
}

function round(value: number): number {
  return Number(value.toFixed(4));
}

function decode(value: string | undefined): string {
  if (value === undefined || value.length === 0) return "";
  return Buffer.from(value, "base64").toString("utf8");
}

async function readJson(file: string): Promise<unknown> {
  if (!(await stat(file)).isFile()) throw new Error(`missing file: ${file}`);
  return JSON.parse(await readFile(file, "utf8"));
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function string(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function number(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("required value is missing");
  return value;
}

const tools: ReadonlyArray<Tool> = ["vibeshield", "codeql", "semgrep", "joern"];

function parseOptions(args: ReadonlyArray<string>): Options {
  const normalized = args[0] === "--" ? args.slice(1) : args;
  const values = new Map<string, string>();
  for (let index = 0; index < normalized.length; index += 2) {
    const name = normalized[index];
    const value = normalized[index + 1];
    if (name === undefined || value === undefined) throw new Error("missing scorer argument");
    values.set(name, value);
  }
  const role = values.get("--role");
  const language = values.get("--language");
  const truth = values.get("--truth");
  const out = values.get("--out");
  const cwes = values.get("--cwes")?.split(",").map(Number).filter(Number.isInteger);
  const selectedTools = (values.get("--tools")?.split(",") ?? [...tools]).filter(isTool);
  const runs = Object.fromEntries(
    selectedTools.map((tool) => [tool, values.get(`--${tool}`)]),
  ) as Partial<Record<Tool, string>>;
  if (
    (role !== "tuning" && role !== "held-out") ||
    (language !== "java" && language !== "python") ||
    truth === undefined ||
    out === undefined ||
    cwes === undefined ||
    cwes.length === 0 ||
    selectedTools.length === 0 ||
    new Set(selectedTools).size !== selectedTools.length ||
    selectedTools.some((tool) => runs[tool] === undefined)
  ) {
    throw new Error(
      "usage: --role <tuning|held-out> --language <java|python> --truth <csv> --cwes <list> [--tools <list>] --vibeshield <run> --codeql <run> --semgrep <run> --joern <run> --out <json>",
    );
  }
  return { role, language, truth, out, cwes, tools: selectedTools, runs };
}

function isTool(value: string): value is Tool {
  return tools.includes(value as Tool);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const output = await scoreOwasp(parseOptions(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}
