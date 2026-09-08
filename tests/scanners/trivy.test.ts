import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { FakeSandboxRuntime } from "../../src/adapters/fake-sandbox.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { scanTrivy } from "../../src/scan/scanners/trivy.js";
import { makeFinding, makeReportInput } from "../support/findings.js";

const guestPath = "../../toolchain/trivy.mjs";
const guest = await import(guestPath);
const raw = JSON.parse(
  await readFile(new URL("../fixtures/scanners/config/trivy.json", import.meta.url), "utf8"),
);
const bundle = {
  digest: "sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c",
  revision: "d7c9302130a9b7e614a5c5d32854f6a08b4bc52e",
  version: "2.2.0",
  reviewedAt: "2026-09-07T00:00:00Z",
};
const snapshot: Snapshot = {
  url: "https://github.com/fixture/config",
  commit: "a".repeat(40),
  files: ["vulnerable.yaml", "fixed.yaml"],
  languages: [],
  history: { commits: 1, truncated: false },
  oversized: 0,
};
const secret = "synthetic-target-value-never-export";
const directories: string[] = [];
afterEach(async () => {
  vi.useRealTimers();
  for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true });
});
function output() {
  return { report: structuredClone(raw), bundle: { ...bundle }, warnings: false };
}
async function context(value: unknown = output(), exitCode = 0, verifyCode = 0) {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-09-07T12:00:00Z"));
  const runtime = new FakeSandboxRuntime({
    exec: (argv) => ({
      exitCode: argv.includes("/usr/local/bin/vibeshield-trivy") ? exitCode : verifyCode,
      stdout: secret,
      stderr: secret,
    }),
  });
  const session = await runtime.create({ name: "trivy-test", imageTag: "fixture" });
  await session.uploadBytes(
    "/work/.vibeshield/exports/trivy.json",
    Buffer.from(typeof value === "string" ? value : JSON.stringify(value)),
  );
  return { session, snapshot, signal: new AbortController().signal };
}
function report(result: Awaited<ReturnType<typeof scanTrivy>>) {
  return buildReport({ ...makeReportInput([result]), policy: defaultPolicy });
}

it("publishes the observed serious built-in check with location, severity and remediation references", async () => {
  const result = await scanTrivy(await context());
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]).toMatchObject({
    scanner: "trivy",
    ruleId: "KSV-0017",
    category: "config",
    severity: "high",
    confidence: "high",
    locations: [{ path: "vulnerable.yaml", line: 15 }],
    remediationKey: "config-privilege",
  });
  expect(result.findings[0]?.evidence).toContain("https://avd.aquasec.com/misconfig/ksv-0017");
  expect(result.findings[0]?.evidence).toContain("securityContext.privileged");
  expect(result.coverage.length).toBeGreaterThan(0);
  expect(result.coverage.every((c) => c.scanner === "trivy" && c.status === "checked")).toBe(true);
  expect(report(result).issues).toHaveLength(1);
  expect(report(result).issues[0]?.prompt).toContain("privileged");
  expect(report(result).issues[0]?.verification).toContain("configuration scan");
});
it("uses exact check IDs rather than guessed titles or a config wildcard", () => {
  for (const ruleId of ["privileged-container", "KSV-0018", "*"]) {
    const finding = makeFinding({
      scanner: "trivy",
      category: "config",
      ruleId,
      title: "Privileged",
      severity: "high",
      confidence: "high",
      remediationKey: "config-privilege",
    });
    expect(report({ findings: [finding], coverage: [] }).issues).toEqual([]);
  }
});
it.each([
  "LOW",
  "MEDIUM",
  "UNKNOWN",
  "invented",
])("keeps %s severity out of important issues", async (severity) => {
  const value = output();
  value.report.Results[0].Misconfigurations[0].Severity = severity;
  const result = await scanTrivy(await context(value));
  expect(result.findings).toHaveLength(1);
  expect(report(result).issues).toEqual([]);
});
it("keeps a valid applicable PASS report complete and empty", async () => {
  const value = output();
  value.report.Results = [value.report.Results[1]];
  const result = await scanTrivy({
    ...(await context(value)),
    snapshot: { ...snapshot, files: ["fixed.yaml"] },
  });
  expect(result.findings).toEqual([]);
  expect(result.coverage.some((c) => c.status === "checked" && c.applicable)).toBe(true);
  expect(report(result).incomplete).toBe(false);
});
it("does not call an empty or missing selected-check result a successful applicable scan", async () => {
  for (const results of [
    [],
    [{ Target: "vulnerable.yaml", Class: "config", Type: "kubernetes", Misconfigurations: [] }],
  ]) {
    const value = output();
    value.report.Results = results;
    expect(report(await scanTrivy(await context(value))).incomplete).toBe(true);
  }
});
it("skips a snapshot without IaC candidates without executing a scanner", async () => {
  const ctx = await context();
  const result = await scanTrivy({
    ...ctx,
    snapshot: { ...snapshot, files: ["app.ts", "README.md"] },
  });
  expect(result).toMatchObject({
    findings: [],
    coverage: [{ scanner: "trivy", status: "skipped", applicable: false }],
  });
  expect(ctx.session.invocations).toEqual([]);
});
it.each([
  "main.tf",
  "Dockerfile",
  "compose.yaml",
])("makes unreviewed or unrecognized %s coverage explicit", async (path) => {
  const value = output();
  value.report.Results = [];
  const result = await scanTrivy({
    ...(await context(value)),
    snapshot: { ...snapshot, files: [path] },
  });
  expect(
    result.coverage.some((c) => c.applicable && ["skipped", "degraded"].includes(c.status)),
  ).toBe(true);
  expect(report(result).incomplete).toBe(true);
});
it("keeps mixed unsupported infrastructure incomplete alongside a real finding", async () => {
  const ctx = await context();
  const result = await scanTrivy({
    ...ctx,
    snapshot: { ...snapshot, files: [...snapshot.files, "main.tf"] },
  });
  expect(report(result).issues).toHaveLength(1);
  expect(report(result).incomplete).toBe(true);
});
it.each([
  "{",
  "null",
  "{}",
])("fails malformed export %s without exposing diagnostics", async (value) => {
  const result = await scanTrivy(await context(value));
  expect(result).toMatchObject({
    findings: [],
    coverage: [expect.objectContaining({ status: "failed" })],
  });
  expect(JSON.stringify(result)).not.toContain(secret);
});
it.each([1, 124, 137])("fails engine exit %s instead of trusting a leftover file", async (code) => {
  const result = await scanTrivy(await context(output(), code));
  expect(result.findings).toEqual([]);
  expect(report(result).incomplete).toBe(true);
});
it("rejects a guest export failing its bounded ownership/size verification", async () => {
  const result = await scanTrivy(await context(output(), 0, 1));
  expect(result.findings).toEqual([]);
  expect(report(result).incomplete).toBe(true);
});
it.each([
  "../escape.yaml",
  "/etc/passwd",
  "other.yaml",
  "dir/../vulnerable.yaml",
  "dir\\vulnerable.yaml",
])("rejects unsafe or non-snapshot target %s", async (path) => {
  const value = output();
  value.report.Results[0].Target = path;
  const result = await scanTrivy(await context(value));
  expect(result.findings).toEqual([]);
  expect(report(result).incomplete).toBe(true);
});
it.each([0, -1, 1.5, undefined])("does not publish without valid source line %s", async (line) => {
  const value = output();
  value.report.Results[0].Misconfigurations[0].CauseMetadata.StartLine = line;
  const result = await scanTrivy(await context(value));
  expect(result.findings).toEqual([]);
  expect(report(result).incomplete).toBe(true);
});
it("rejects missing, mismatched, or unsupported engine and bundle metadata", async () => {
  for (const alter of [
    (value: ReturnType<typeof output>) => {
      value.bundle = undefined as never;
    },
    (value: ReturnType<typeof output>) => {
      value.bundle.digest = `sha256:${"0".repeat(64)}`;
    },
    (value: ReturnType<typeof output>) => {
      value.bundle.version = "1.0.0";
    },
    (value: ReturnType<typeof output>) => {
      value.report.Trivy.Version = "0.73.0";
    },
  ]) {
    const value = output();
    alter(value);
    const result = await scanTrivy(await context(value));
    expect(result.findings).toEqual([]);
    expect(report(result).incomplete).toBe(true);
  }
});
it("discloses an aged frozen bundle while retaining observed evidence", async () => {
  const ctx = await context();
  vi.setSystemTime(new Date("2026-10-08T00:00:00Z"));
  const result = await scanTrivy(ctx);
  expect(report(result).issues).toHaveLength(1);
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "check-bundle", status: "degraded" }),
  );
  expect(report(result).incomplete).toBe(true);
});
it("preserves scanner warnings as coverage loss without diagnostics", async () => {
  const value = output();
  value.warnings = true;
  const result = await scanTrivy(await context(value));
  expect(report(result).issues).toHaveLength(1);
  expect(report(result).incomplete).toBe(true);
  expect(JSON.stringify(result)).not.toContain(secret);
});
it("propagates cancellation", async () => {
  const ctx = await context();
  const controller = new AbortController();
  controller.abort(new Error("cancelled"));
  await expect(scanTrivy({ ...ctx, signal: controller.signal })).rejects.toThrow("cancelled");
});
it("removes target messages, snippets and irrelevant metadata before export", () => {
  const value = structuredClone(raw);
  value.ArtifactName = secret;
  const item = value.Results[0].Misconfigurations[0];
  item.Message = secret;
  item.CauseMetadata.Code = { Lines: [{ Content: secret }] };
  const clean = guest.sanitizeTrivy(value);
  expect(JSON.stringify(clean)).not.toContain(secret);
  expect(clean.Results[0].Misconfigurations[0]).toMatchObject({
    ID: "KSV-0017",
    Severity: "HIGH",
    CauseMetadata: { StartLine: 15 },
  });
});
it("uses file output, frozen checks, and service config and ignore without dependency scanners", () => {
  const argv = guest.trivyCommand();
  for (const flag of [
    "config",
    "--skip-check-update",
    "--skip-version-check",
    "--disable-telemetry",
    "--include-non-failures",
    "--misconfig-scanners=kubernetes",
    "--config=/opt/vibeshield/trivy.yaml",
    "--ignorefile=/opt/vibeshield/empty.ignore",
    "--output=/work/.vibeshield/trivy-raw.json",
    "--exit-code=0",
  ])
    expect(argv).toContain(flag);
  expect(argv).not.toContain("--scanners=vuln");
});
it("rejects an absent or symlinked check bundle before execution can fall back to embedded checks", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "vibeshield-trivy-bundle-test-")));
  directories.push(root);
  expect(() => guest.verifyTrivyBundle(root)).toThrow();
  await mkdir(join(root, "cache/policy"), { recursive: true });
  await writeFile(
    join(root, "manifest.json"),
    await readFile(new URL("../../toolchain/trivy-manifest.json", import.meta.url)),
  );
  await writeFile(
    join(root, "cache/policy/metadata.json"),
    JSON.stringify({ Digest: bundle.digest, MajorVersion: 2 }),
  );
  await symlink(root, join(root, "cache/policy/content"));
  expect(() => guest.verifyTrivyBundle(root)).toThrow();
});
