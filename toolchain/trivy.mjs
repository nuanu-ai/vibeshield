#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, lstatSync, openSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  gitEnvironment,
  readBoundedJson,
  readBoundedText,
  SERVICE,
  writeExport,
} from "./export-results.mjs";

const ROOT = "/opt/vibeshield/trivy";
const RAW = `${SERVICE}/trivy-raw.json`;
const object = (value) =>
  value && typeof value === "object" && !Array.isArray(value) ? value : {};
const list = (value, fn) => (Array.isArray(value) ? value.map(fn) : null);
export function sanitizeTrivy(value) {
  const document = object(value);
  return {
    SchemaVersion: document.SchemaVersion,
    Trivy: { Version: object(document.Trivy).Version },
    ArtifactType: document.ArtifactType,
    Results: list(document.Results ?? [], (raw) => {
      const result = object(raw);
      return {
        Target: result.Target,
        Class: result.Class,
        Type: result.Type,
        Misconfigurations: list(result.Misconfigurations ?? [], (raw) => {
          const item = object(raw);
          // PASS rows prove that a selected rule ran even when it had no finding.
          if (item.Status === "PASS") return { ID: item.ID, Status: item.Status };
          return {
            ID: item.ID,
            Title: item.Title,
            Description: item.Description,
            Namespace: item.Namespace,
            Query: item.Query,
            Resolution: item.Resolution,
            Severity: item.Severity,
            PrimaryURL: item.PrimaryURL,
            References: item.References,
            Status: item.Status,
            CauseMetadata: {
              StartLine: object(item.CauseMetadata).StartLine,
              EndLine: object(item.CauseMetadata).EndLine,
            },
          };
        }),
      };
    }),
  };
}
export function trivyCommand() {
  return [
    "config",
    "--config=/opt/vibeshield/trivy.yaml",
    `--cache-dir=${ROOT}/cache`,
    "--ignorefile=/opt/vibeshield/empty.ignore",
    "--format=json",
    `--output=${RAW}`,
    "--skip-check-update",
    "--skip-version-check",
    "--disable-telemetry",
    "--include-non-failures",
    "--misconfig-scanners=kubernetes",
    "--rego-error-limit=0",
    "--exit-code=0",
    "/work/snapshot",
  ];
}
export function verifyTrivyBundle(root = ROOT) {
  const manifest = readBoundedJson(`${root}/manifest.json`);
  const metadata = readBoundedJson(`${root}/cache/policy/metadata.json`);
  if (
    manifest.engineVersion !== "0.72.0" ||
    manifest.bundle?.version !== "2.2.0" ||
    manifest.bundle.digest !==
      "sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c" ||
    metadata.Digest !== manifest.bundle.digest ||
    metadata.MajorVersion !== 2 ||
    metadata.CustomBuild
  )
    throw new Error();
  const directory = `${root}/cache/policy/content`;
  if (realpathSync(directory) !== directory || !lstatSync(directory).isDirectory())
    throw new Error();
  const paths = readdirSync(directory, { recursive: true });
  const files = [];
  for (const relative of paths) {
    const path = `${directory}/${relative}`;
    const stat = lstatSync(path);
    if (
      stat.isSymbolicLink() ||
      (!stat.isDirectory() && !stat.isFile()) ||
      stat.uid !== process.getuid() ||
      stat.mode & 0o022
    )
      throw new Error();
    if (stat.isFile()) files.push(relative);
  }
  const hash = createHash("sha256");
  for (const relative of files.sort()) {
    hash
      .update(relative)
      .update("\0")
      .update(
        createHash("sha256")
          .update(readFileSync(`${directory}/${relative}`))
          .digest("hex"),
      )
      .update("\n");
  }
  if (
    files.length !== 641 ||
    hash.digest("hex") !== "3a42784bbcbfc0468b8b4328004d6e27282053afa428b322eeae6972727d01f8"
  )
    throw new Error();
  return manifest;
}
function main() {
  const manifest = verifyTrivyBundle();
  // Both settings files are image-owned, even when the target has identically named files.
  if (
    readBoundedJson("/opt/vibeshield/trivy.yaml").constructor !== Object ||
    lstatSync("/opt/vibeshield/empty.ignore").size !== 0 ||
    realpathSync("/opt/vibeshield/empty.ignore") !== "/opt/vibeshield/empty.ignore"
  )
    throw new Error();
  const version = spawnSync("/usr/local/bin/trivy", ["--version"], {
    cwd: SERVICE,
    env: gitEnvironment(),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 10_000,
    maxBuffer: 65536,
  });
  if (version.status !== 0 || version.stdout.trim() !== `Version: ${manifest.engineVersion}`)
    throw new Error();
  const logPath = `${SERVICE}/trivy-log.txt`;
  const log = openSync(logPath, "wx", 0o600);
  let child;
  try {
    child = spawnSync("/usr/local/bin/trivy", trivyCommand(), {
      cwd: SERVICE,
      env: gitEnvironment(),
      stdio: ["ignore", "ignore", log],
      timeout: 115_000,
    });
  } finally {
    closeSync(log);
  }
  if (child.error || child.signal || child.status !== 0) throw new Error();
  const diagnostics = readBoundedText(logPath);
  // Warnings (including YAML/JSON parse failures) stay boolean, never raw text.
  const warnings = /\b(?:WARN|ERROR|FATAL)\b/.test(diagnostics);
  writeExport(`${SERVICE}/exports/trivy.json`, {
    report: sanitizeTrivy(readBoundedJson(RAW)),
    bundle: manifest.bundle,
    warnings,
  });
}
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stderr.write("Configuration scan export failed\n");
    process.exitCode = 1;
  }
}
