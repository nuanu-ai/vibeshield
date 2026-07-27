#!/usr/bin/env tsx
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

type Tool = "codeql" | "joern" | "semgrep" | "vibeshield";

interface Options {
  readonly tool: Tool;
  readonly run: string;
  readonly out: string;
}

interface Alert {
  readonly cwe: number;
  readonly path: string;
  readonly line?: number;
  readonly ruleId: string;
  readonly message?: string;
  readonly sourcePath?: string;
  readonly sourceLine?: number;
}

export async function normalizeResults(options: Options): Promise<Record<string, unknown>> {
  const run = path.resolve(options.run);
  const manifest = await readJson(path.join(run, "run-manifest.json"));
  if (record(manifest)?.state !== "complete") {
    throw new Error(`run is not complete: ${run}`);
  }
  const alerts = deduplicate(await normalize(options.tool, run));
  const output = {
    schemaVersion: 1,
    identity: "explicit tool CWE plus raw result location; no benchmark labels or report grouping",
    tool: options.tool,
    target: record(record(manifest)?.target),
    configuration: record(record(manifest)?.configuration),
    alertCount: alerts.length,
    alerts,
  };
  await writeFile(options.out, `${JSON.stringify(output, null, 2)}\n`);
  return output;
}

async function normalize(tool: Tool, run: string): Promise<Alert[]> {
  switch (tool) {
    case "codeql":
      return normalizeSarif(await readJson(path.join(run, "results.sarif")));
    case "semgrep":
      return normalizeSemgrep(await readJson(path.join(run, "results.json")));
    case "joern":
      return normalizeJoern(await readFile(path.join(run, "results.tsv"), "utf8"));
    case "vibeshield":
      return normalizeVibeShield(await readVibeShieldReport(run));
  }
}

function normalizeSarif(input: unknown): Alert[] {
  return array(record(input)?.runs).flatMap((rawRun) => {
    const run = record(rawRun);
    const rules = new Map<string, number[]>();
    for (const rawRule of array(record(record(run?.tool)?.driver)?.rules)) {
      const rule = record(rawRule);
      const id = string(rule?.id);
      if (id !== undefined) rules.set(id, extractCwes(rule));
    }
    return array(run?.results).flatMap((rawResult) => {
      const result = record(rawResult);
      const ruleId = string(result?.ruleId);
      const location = firstLocation(result);
      if (ruleId === undefined || location === undefined) return [];
      const message = string(record(result?.message)?.text);
      return (rules.get(ruleId) ?? extractCwes(result)).map((cwe) => ({
        cwe,
        ...location,
        ruleId,
        ...(message === undefined ? {} : { message }),
      }));
    });
  });
}

function normalizeSemgrep(input: unknown): Alert[] {
  return array(record(input)?.results).flatMap((rawResult) => {
    const result = record(rawResult);
    const resultPath = string(result?.path);
    const ruleId = string(result?.check_id);
    const extra = record(result?.extra);
    if (resultPath === undefined || ruleId === undefined) return [];
    const line = number(record(result?.start)?.line);
    const message = string(extra?.message);
    return extractCwes(record(extra?.metadata)).map((cwe) => ({
      cwe,
      path: resultPath,
      ...(line === undefined ? {} : { line }),
      ruleId,
      ...(message === undefined ? {} : { message }),
    }));
  });
}

function normalizeJoern(input: string): Alert[] {
  return input
    .split(/\r?\n/u)
    .slice(1)
    .filter(Boolean)
    .flatMap((row) => {
      const fields = row.split("\t");
      const cwe = Number(fields[0]);
      if (!Number.isInteger(cwe)) return [];
      const line = integer(fields[3]);
      const sourceLine = integer(fields[6]);
      return [
        {
          cwe,
          path: decode(fields[2]),
          ...(line === undefined ? {} : { line }),
          ruleId: `direct-joern-cwe-${cwe}`,
          message: decode(fields[4]),
          sourcePath: decode(fields[5]),
          ...(sourceLine === undefined ? {} : { sourceLine }),
        },
      ];
    });
}

function normalizeVibeShield(input: unknown): Alert[] {
  const assessment = record(record(input)?.assessment);
  return array(assessment?.findings).flatMap((rawFinding) => {
    const finding = record(rawFinding);
    const ruleId = string(finding?.ruleId);
    if (ruleId === undefined) return [];
    const cwes = extractCwes({ ruleId, category: finding?.category });
    return array(finding?.locations).flatMap((rawLocation) => {
      const location = record(rawLocation);
      const file = string(location?.filePath);
      if (file === undefined) return [];
      const line = number(location?.startLine);
      return cwes.map((cwe) => ({
        cwe,
        path: file,
        ...(line === undefined ? {} : { line }),
        ruleId,
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

function firstLocation(result: Record<string, unknown> | undefined) {
  const location = record(array(result?.locations)[0]);
  const physical = record(location?.physicalLocation);
  const artifact = record(physical?.artifactLocation);
  const region = record(physical?.region);
  const resultPath = string(artifact?.uri);
  if (resultPath === undefined) return undefined;
  const line = number(region?.startLine);
  return { path: resultPath, ...(line === undefined ? {} : { line }) };
}

function extractCwes(value: unknown): number[] {
  const matches = JSON.stringify(value).matchAll(/cwe(?:[-_/ ]|%2f)*(?:cwe[-_/ ]*)?0*(\d{1,4})/giu);
  return [...new Set([...matches].map((match) => Number(match[1])).filter(Number.isInteger))].sort(
    (left, right) => left - right,
  );
}

function deduplicate(alerts: ReadonlyArray<Alert>): Alert[] {
  const seen = new Set<string>();
  return alerts.filter((alert) => {
    const key = [
      alert.cwe,
      alert.path,
      alert.line ?? "",
      alert.ruleId,
      alert.sourcePath ?? "",
      alert.sourceLine ?? "",
    ].join(":");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function decode(value: string | undefined): string {
  return value === undefined ? "" : Buffer.from(value, "base64").toString("utf8");
}

function integer(value: string | undefined): number | undefined {
  const parsed = Number(value);
  return Number.isInteger(parsed) ? parsed : undefined;
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

function parseOptions(args: ReadonlyArray<string>): Options {
  const normalized = args[0] === "--" ? args.slice(1) : args;
  const values = new Map<string, string>();
  for (let index = 0; index < normalized.length; index += 2) {
    const name = normalized[index];
    const value = normalized[index + 1];
    if (name === undefined || value === undefined) throw new Error("missing normalizer argument");
    values.set(name, value);
  }
  const tool = values.get("--tool");
  const run = values.get("--run");
  const out = values.get("--out");
  if (!isTool(tool) || run === undefined || out === undefined) {
    throw new Error("usage: --tool <tool> --run <run-directory> --out <json>");
  }
  return { tool, run, out };
}

function isTool(value: string | undefined): value is Tool {
  return value === "codeql" || value === "joern" || value === "semgrep" || value === "vibeshield";
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const output = await normalizeResults(parseOptions(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}
