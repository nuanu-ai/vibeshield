#!/usr/bin/env node

import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const DEFAULT_BATCH_SIZE = 1000;
const DEFAULT_TIMEOUT_MS = 45_000;
const OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch";

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  process.stdout.write("usage: vibeshield-osv-scan --source <dir> --output <json>\n");
  process.exit(0);
}
if (args.source === undefined || args.output === undefined) {
  process.stderr.write("vibeshield-osv-scan requires --source and --output\n");
  process.exit(2);
}

const queries = await collectNpmQueries(args.source);
const results = await queryOsv(queries);
await writeFile(
  args.output,
  JSON.stringify(
    {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      source: args.source,
      queryCount: queries.length,
      results,
    },
    null,
    2,
  ),
);

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      out.help = true;
      continue;
    }
    if (arg === "--source") {
      i += 1;
      out.source = argv[i];
      continue;
    }
    if (arg === "--output") {
      i += 1;
      out.output = argv[i];
    }
  }
  return out;
}

async function collectNpmQueries(sourceDir) {
  const packageJsonPaths = await findPackageJson(sourceDir);
  const out = [];
  const seen = new Set();
  for (const packageJsonPath of packageJsonPaths) {
    const repoPath = path.posix.normalize(
      path.relative(sourceDir, packageJsonPath).split(path.sep).join(path.posix.sep),
    );
    const parsed = JSON.parse(await readFile(packageJsonPath, "utf8"));
    for (const scope of [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies",
    ]) {
      const deps = isRecord(parsed[scope]) ? parsed[scope] : {};
      for (const [name, rawVersion] of Object.entries(deps)) {
        if (typeof rawVersion !== "string") {
          continue;
        }
        const version = exactNpmVersion(rawVersion);
        if (version === undefined) {
          continue;
        }
        const key = ["npm", name, version, repoPath].join("\0");
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        out.push({
          target: repoPath,
          packageName: name,
          ecosystem: "npm",
          version,
          dependencyScope: scope,
          query: {
            package: { ecosystem: "npm", name },
            version,
          },
        });
      }
    }
  }
  return out;
}

async function findPackageJson(root) {
  const out = [];
  await walk(root, out);
  return out.sort();
}

async function walk(dir, out) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist") {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(fullPath, out);
      continue;
    }
    if (entry.isFile() && entry.name === "package.json") {
      out.push(fullPath);
    }
  }
}

function exactNpmVersion(raw) {
  const npmAlias = raw.match(/^npm:[^@]+@(.+)$/)?.[1];
  const value = (npmAlias ?? raw).trim();
  if (
    value === "" ||
    value.startsWith("^") ||
    value.startsWith("~") ||
    value.startsWith(">") ||
    value.startsWith("<") ||
    value.startsWith("=") ||
    value.includes(" ") ||
    value.includes("||") ||
    value.includes(" - ") ||
    value === "*" ||
    /^[a-z]+:/i.test(value)
  ) {
    return undefined;
  }
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value) ? value : undefined;
}

async function queryOsv(queries) {
  const out = [];
  for (let i = 0; i < queries.length; i += DEFAULT_BATCH_SIZE) {
    const batch = queries.slice(i, i + DEFAULT_BATCH_SIZE);
    const response = await postJsonWithTimeout(
      OSV_QUERY_BATCH_URL,
      { queries: batch.map((item) => item.query) },
      DEFAULT_TIMEOUT_MS,
    );
    const results = Array.isArray(response.results) ? response.results : [];
    for (let j = 0; j < batch.length; j += 1) {
      const item = batch[j];
      const result = isRecord(results[j]) ? results[j] : {};
      const vulns = Array.isArray(result.vulns) ? result.vulns : [];
      if (vulns.length === 0) {
        continue;
      }
      out.push({
        target: item.target,
        packageName: item.packageName,
        ecosystem: item.ecosystem,
        version: item.version,
        dependencyScope: item.dependencyScope,
        vulns,
      });
    }
  }
  return out;
}

async function postJsonWithTimeout(url, body, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  timeout.unref();
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`OSV returned HTTP ${response.status}: ${await response.text()}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
