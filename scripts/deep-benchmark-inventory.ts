#!/usr/bin/env tsx
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

interface GroundTruthExpectationFile {
  readonly version: 1;
  readonly repositories: ReadonlyArray<{
    readonly groundTruth?: ReadonlyArray<{ readonly id: string }>;
  }>;
}

interface InventoryFile {
  readonly version: 1;
  readonly repositories: ReadonlyArray<InventoryRepository>;
}

interface InventoryRepository {
  readonly id: string;
  readonly name: string;
  readonly source: {
    readonly kind: "juice-shop-challenges";
    readonly relativePath: string;
  };
  readonly categoryCoverage: Readonly<Record<string, InventoryCategoryCoverage>>;
}

interface InventoryCategoryCoverage {
  readonly groundTruthIds?: ReadonlyArray<string>;
  readonly limitation?: string;
  readonly note?: string;
}

export interface JuiceShopChallenge {
  readonly key: string;
  readonly name: string;
  readonly category: string;
}

interface InventoryAuditOptions {
  readonly failOnLimitations: boolean;
  readonly sources: Readonly<Record<string, string>>;
  readonly expectationIds: ReadonlySet<string>;
}

interface InventoryAuditSummary {
  readonly repositoryId: string;
  readonly name: string;
  readonly challengeCount: number;
  readonly categoryCount: number;
  readonly coveredCategories: number;
  readonly limitationCategories: number;
  readonly errors: ReadonlyArray<string>;
}

interface CliOptions {
  readonly expectPath: string;
  readonly inventoryPath: string;
  readonly sources: Readonly<Record<string, string>>;
  readonly jsonOutput: boolean;
  readonly failOnLimitations: boolean;
}

const mainModulePath = process.argv[1] === undefined ? undefined : path.resolve(process.argv[1]);
if (mainModulePath !== undefined && fileURLToPath(import.meta.url) === mainModulePath) {
  const options = parseArgs(process.argv.slice(2));
  const expectationIds = await loadGroundTruthIds(options.expectPath);
  const inventory = await loadInventory(options.inventoryPath);
  const summaries = await auditInventory(inventory, {
    failOnLimitations: options.failOnLimitations,
    sources: options.sources,
    expectationIds,
  });
  const failed = summaries.some((summary) => summary.errors.length > 0);

  if (options.jsonOutput) {
    process.stdout.write(`${JSON.stringify(summaries, null, 2)}\n`);
  } else {
    for (const summary of summaries) {
      const status = summary.errors.length === 0 ? "PASS" : "FAIL";
      process.stdout.write(
        `${status} ${summary.name} challenges=${summary.challengeCount} categories=${summary.categoryCount} coveredCategories=${summary.coveredCategories} limitationCategories=${summary.limitationCategories}\n`,
      );
      for (const error of summary.errors) {
        process.stdout.write(`  error: ${error}\n`);
      }
    }
  }

  process.exit(failed ? 1 : 0);
}

export function parseJuiceShopChallenges(input: string): JuiceShopChallenge[] {
  const normalized = input.replace(/^---\s*\n/, "");
  const blocks = normalized
    .split(/\n(?=-\n)/)
    .map((block) => block.trim())
    .filter((block) => block.startsWith("-"));
  const out: JuiceShopChallenge[] = [];

  for (const block of blocks) {
    const key = scalarField(block, "key");
    const name = scalarField(block, "name");
    const category = scalarField(block, "category");
    if (key === undefined && name === undefined && category === undefined) {
      continue;
    }
    if (key === undefined || name === undefined || category === undefined) {
      throw new Error(`Juice Shop challenge block is missing key, name, or category: ${block}`);
    }
    out.push({ key, name, category });
  }

  return out.sort((a, b) => a.key.localeCompare(b.key));
}

export async function auditInventory(
  inventory: InventoryFile,
  options: InventoryAuditOptions,
): Promise<InventoryAuditSummary[]> {
  return await Promise.all(
    inventory.repositories.map(async (repository) => {
      const sourceRoot = options.sources[repository.id];
      if (sourceRoot === undefined) {
        return summaryWithErrors(repository, [`missing --source ${repository.id}=<repo-root>`]);
      }
      const sourcePath = path.join(sourceRoot, repository.source.relativePath);
      const challenges = parseJuiceShopChallenges(await readFile(sourcePath, "utf8"));
      return auditRepository(repository, challenges, options);
    }),
  );
}

function auditRepository(
  repository: InventoryRepository,
  challenges: ReadonlyArray<JuiceShopChallenge>,
  options: InventoryAuditOptions,
): InventoryAuditSummary {
  const categories = new Map<string, number>();
  for (const challenge of challenges) {
    categories.set(challenge.category, (categories.get(challenge.category) ?? 0) + 1);
  }
  const categoryNames = new Set(categories.keys());
  const errors: string[] = [];
  let coveredCategories = 0;
  let limitationCategories = 0;

  for (const [category, count] of [...categories.entries()].sort((a, b) =>
    a[0].localeCompare(b[0]),
  )) {
    const coverage = repository.categoryCoverage[category];
    if (coverage === undefined) {
      errors.push(`category ${category} has ${count} challenges but no inventory coverage policy`);
      continue;
    }
    const ids = coverage.groundTruthIds ?? [];
    if (ids.length === 0 && coverage.limitation === undefined) {
      errors.push(`category ${category} coverage must name groundTruthIds or a limitation`);
      continue;
    }
    for (const id of ids) {
      if (!options.expectationIds.has(id)) {
        errors.push(`category ${category} references missing groundTruth id: ${id}`);
      }
    }
    if (ids.length > 0) {
      coveredCategories += 1;
    }
    if (coverage.limitation !== undefined) {
      limitationCategories += 1;
      if (options.failOnLimitations) {
        errors.push(`category ${category} has documented limitation: ${coverage.limitation}`);
      }
    }
  }

  for (const category of Object.keys(repository.categoryCoverage).sort()) {
    if (!categoryNames.has(category)) {
      errors.push(`category coverage policy has no matching challenge category: ${category}`);
    }
  }

  return {
    repositoryId: repository.id,
    name: repository.name,
    challengeCount: challenges.length,
    categoryCount: categories.size,
    coveredCategories,
    limitationCategories,
    errors,
  };
}

function summaryWithErrors(
  repository: InventoryRepository,
  errors: ReadonlyArray<string>,
): InventoryAuditSummary {
  return {
    repositoryId: repository.id,
    name: repository.name,
    challengeCount: 0,
    categoryCount: 0,
    coveredCategories: 0,
    limitationCategories: 0,
    errors,
  };
}

function scalarField(block: string, field: string): string | undefined {
  const match = block.match(new RegExp(`^\\s*${field}:\\s*(.+)$`, "m"));
  if (match?.[1] === undefined) {
    return undefined;
  }
  return parseYamlScalar(match[1]);
}

function parseYamlScalar(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (trimmed === "~" || trimmed === "") {
    return undefined;
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\"/g, '"');
  }
  return trimmed;
}

async function loadGroundTruthIds(expectPath: string): Promise<ReadonlySet<string>> {
  const parsed = JSON.parse(
    await readFile(path.resolve(expectPath), "utf8"),
  ) as GroundTruthExpectationFile;
  if (parsed.version !== 1 || !Array.isArray(parsed.repositories)) {
    throw new Error(`Invalid benchmark expectation file: ${expectPath}`);
  }
  return new Set(
    parsed.repositories.flatMap((repository) =>
      (repository.groundTruth ?? []).map((item: { readonly id: string }) => item.id),
    ),
  );
}

async function loadInventory(inventoryPath: string): Promise<InventoryFile> {
  const parsed = JSON.parse(await readFile(path.resolve(inventoryPath), "utf8")) as InventoryFile;
  if (parsed.version !== 1 || !Array.isArray(parsed.repositories)) {
    throw new Error(`Invalid benchmark inventory file: ${inventoryPath}`);
  }
  return parsed;
}

function parseArgs(args: ReadonlyArray<string>): CliOptions {
  let expectPath = "benchmarks/deep-static-training-ground-truth.json";
  let inventoryPath = "benchmarks/deep-static-training-inventory.json";
  let jsonOutput = false;
  let failOnLimitations = false;
  const sources: Record<string, string> = {};

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      jsonOutput = true;
      continue;
    }
    if (arg === "--fail-on-limitations") {
      failOnLimitations = true;
      continue;
    }
    if (arg === "--expect") {
      const value = args[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new Error("--expect requires a file path");
      }
      expectPath = value;
      index += 1;
      continue;
    }
    if (arg === "--inventory") {
      const value = args[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new Error("--inventory requires a file path");
      }
      inventoryPath = value;
      index += 1;
      continue;
    }
    if (arg === "--source") {
      const value = args[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new Error("--source requires id=repo-root");
      }
      addSource(sources, value);
      index += 1;
      continue;
    }
    if (arg?.startsWith("--source=") === true) {
      addSource(sources, arg.slice("--source=".length));
      continue;
    }
    if (arg?.startsWith("--") === true) {
      throw new Error(`Unknown option: ${arg}`);
    }
    throw new Error(`Unexpected positional argument: ${arg}`);
  }

  return { expectPath, inventoryPath, sources, jsonOutput, failOnLimitations };
}

function addSource(sources: Record<string, string>, raw: string): void {
  const separator = raw.indexOf("=");
  if (separator <= 0 || separator === raw.length - 1) {
    throw new Error("--source value must use id=repo-root");
  }
  sources[raw.slice(0, separator)] = path.resolve(raw.slice(separator + 1));
}
