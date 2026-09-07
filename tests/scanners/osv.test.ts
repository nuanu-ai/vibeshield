import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";
import { FakeSandboxRuntime } from "../../src/adapters/fake-sandbox.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { readOsvAdvisoryData, scanOsv } from "../../src/scan/scanners/osv.js";
import { makeReportInput } from "../support/findings.js";

const guestPath = "../../toolchain/osv.mjs";
const guest = await import(guestPath);
const secret = "synthetic-repository-diagnostic-never-export";
const snapshot: Snapshot = {
  url: "https://github.com/fixture/dependencies",
  commit: "a".repeat(40),
  files: ["package-lock.json"],
  languages: ["JavaScript"],
  history: { commits: 1, truncated: false },
};
// Sanitized subset captured from v2.3.8 in Microsandbox on 2026-09-07.
// Retains the official results/source/packages/vulnerabilities/groups schema.
function member<T>(items: T[], index = 0): T {
  const item = items[index];
  if (item === undefined) throw new Error("Missing captured fixture member");
  return item;
}
function official() {
  return {
    results: [
      {
        source: { path: "/work/snapshot/package-lock.json", type: "lockfile" },
        packages: [
          {
            package: { name: "lodash", version: "4.17.20", ecosystem: "npm" },
            dependency_groups: ["dev"],
            groups: [
              {
                ids: ["GHSA-29mw-wpgm-hmr9"],
                aliases: ["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9"],
                max_severity: "5.3",
              },
            ],
            vulnerabilities: [
              {
                id: "GHSA-29mw-wpgm-hmr9",
                aliases: ["CVE-2020-28500"],
                summary: "Regular Expression Denial of Service (ReDoS) in lodash",
                database_specific: { severity: "MODERATE" },
                affected: [
                  {
                    package: { ecosystem: "npm", name: "lodash" },
                    ranges: [
                      { type: "SEMVER", events: [{ introduced: "4.0.0" }, { fixed: "4.17.21" }] },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
    experimental_config: { licenses: { summary: false, allowlist: null } },
  };
}
function envelope(output: unknown = official(), exitCode = 1) {
  return {
    scannerVersion: "2.3.8",
    exitCode,
    diagnostics: false,
    workspaceMembers: [] as { manifest: string; lockfile: string }[],
    advisoryData: { source: "OSV", retrievedAt: "2026-09-07T12:00:00.000Z", stale: false },
    output,
  };
}
async function context(value: unknown = envelope(), files = snapshot.files, processExit = 0) {
  const runtime = new FakeSandboxRuntime({
    exec: (argv) => ({
      exitCode: argv.includes("/usr/local/bin/vibeshield-osv") ? processExit : 0,
      stdout: secret,
      stderr: secret,
    }),
  });
  const session = await runtime.create({ name: "osv-test", imageTag: "fixture" });
  await session.uploadBytes(
    "/work/.vibeshield/exports/osv.json",
    Buffer.from(typeof value === "string" ? value : JSON.stringify(value)),
  );
  return { session, snapshot: { ...snapshot, files }, signal: new AbortController().signal };
}
it("retains installed lockfile version, dev scope, advisory aliases and matching-package fixes", async () => {
  const raw = official();
  member(member(member(raw.results).packages).vulnerabilities).aliases.push("GHSA-synthetic-alias");
  member(member(member(raw.results).packages).vulnerabilities).affected.push({
    package: { ecosystem: "npm", name: "other-package" },
    ranges: [{ type: "SEMVER", events: [{ fixed: "99.0.0" }] }],
  });
  const result = await scanOsv(await context(envelope(raw)));
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]).toMatchObject({
    severity: "medium",
    dependency: {
      name: "lodash",
      version: "4.17.20",
      ecosystem: "npm",
      manifest: "package-lock.json",
      scope: "development",
      advisoryIds: expect.arrayContaining([
        "GHSA-29mw-wpgm-hmr9",
        "CVE-2020-28500",
        "GHSA-synthetic-alias",
      ]),
      fixedVersions: ["4.17.21"],
    },
  });
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "package-lock.json", status: "checked", applicable: true }),
  );
  expect(JSON.stringify(result)).not.toContain(secret);
});
it("keeps separate manifests and installed versions through report grouping, including dev advisories", async () => {
  const raw = official();
  const first = member(raw.results);
  member(member(first.packages).vulnerabilities).database_specific.severity = "HIGH";
  raw.results.push(structuredClone(first));
  member(raw.results, 1).source.path = "/work/snapshot/frontend/package-lock.json";
  member(member(raw.results, 1).packages).package.version = "4.17.19";
  const result = await scanOsv(
    await context(envelope(raw), ["package-lock.json", "frontend/package-lock.json"]),
  );
  expect(result.findings.map((x) => [x.dependency?.manifest, x.dependency?.version])).toEqual([
    ["package-lock.json", "4.17.20"],
    ["frontend/package-lock.json", "4.17.19"],
  ]);
  expect(new Set(result.findings.map((x) => x.id)).size).toBe(2);
  expect(buildReport({ ...makeReportInput([result]), policy: defaultPolicy }).issues).toHaveLength(
    2,
  );
});
it.each([
  ["CRITICAL", "critical"],
  ["HIGH", "high"],
  ["MODERATE", "medium"],
  ["LOW", "low"],
  ["unknown", "unknown"],
  ["", "unknown"],
])("uses advisory metadata severity %s without upgrading unknown", async (label, want) => {
  const raw = official();
  member(member(member(raw.results).packages).vulnerabilities).database_specific.severity =
    label ?? "";
  const result = await scanOsv(await context(envelope(raw)));
  expect(result.findings[0]?.severity).toBe(want);
  expect(result.coverage[0]?.status).toBe(want === "unknown" ? "degraded" : "checked");
  expect(buildReport({ ...makeReportInput([result]), policy: defaultPolicy }).issues.length).toBe(
    ["high", "critical"].includes(want ?? "") ? 1 : 0,
  );
});
it.each([
  "^4.17.0",
  "~4.17.20",
  "*",
  "",
  "file:../lodash",
  "https://example.test/pkg.tgz",
])("refuses non-installed npm version %s rather than guessing", async (version) => {
  const raw = official();
  member(member(raw.results).packages).package.version = version;
  const result = await scanOsv(await context(envelope(raw)));
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]?.status).toBe("degraded");
});
it.each([
  ["package.json"],
  ["custom.lock"],
  ["Cargo.lock"],
  ["requirements.txt"],
  ["npm-shrinkwrap.json"],
])("reports unsupported or missing lockfile %s explicitly", async (file) => {
  const ctx = await context(envelope(), [file]);
  const result = await scanOsv(ctx);
  expect(result.findings).toEqual([]);
  expect(result.coverage).toContainEqual(
    expect.objectContaining({
      status: "skipped",
      applicable: true,
      reason: expect.stringMatching(/lockfile|supported/i),
    }),
  );
  expect(ctx.session.invocations).toEqual([]);
});
it("enumerates supported lockfiles and exposes omissions in an otherwise successful scan", async () => {
  const result = await scanOsv(
    await context(envelope(), [
      "package-lock.json",
      "frontend/pnpm-lock.yaml",
      "yarn.lock",
      "bun.lock",
      "unknown.lock",
    ]),
  );
  for (const file of ["frontend/pnpm-lock.yaml", "yarn.lock", "bun.lock"])
    expect(result.coverage).toContainEqual(
      expect.objectContaining({ area: file, status: "degraded", applicable: true }),
    );
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "unknown.lock", status: "skipped", applicable: true }),
  );
  expect(result.findings).toHaveLength(1);
  expect(buildReport({ ...makeReportInput([result]), policy: defaultPolicy }).incomplete).toBe(
    true,
  );
});
it("requires actual package inventory to mark a fixed lockfile checked", async () => {
  const raw = official();
  const pkg = member(member(raw.results).packages);
  pkg.package.version = "4.18.0";
  pkg.vulnerabilities = [];
  pkg.groups = [];
  expect(await scanOsv(await context(envelope(raw, 0)))).toMatchObject({
    findings: [],
    coverage: [{ area: "package-lock.json", status: "checked" }],
  });
  expect((await scanOsv(await context(envelope({ results: [] }, 0)))).coverage[0]?.status).toBe(
    "degraded",
  );
  member(raw.results).packages = [];
  expect((await scanOsv(await context(envelope(raw, 0)))).coverage[0]?.status).toBe("degraded");
});
it.each([
  null,
  {},
  "{",
  "[]",
  `{}${" ".repeat(8 * 1024 * 1024)}`,
])("fails malformed or oversized exports without stdout fallback", async (value) => {
  const result = await scanOsv(await context(value));
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]?.status).toBe("failed");
  expect(JSON.stringify(result)).not.toContain(secret);
});
it.each([
  124, 127, 128, 129, 130, 2,
])("records scanner exit %s as explicit failed coverage", async (exitCode) => {
  const result = await scanOsv(await context(envelope(official(), exitCode)));
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]).toMatchObject({ status: "failed", applicable: true });
});
it("handles API timeout and wrapper failure without trusting an old successful export", async () => {
  for (const exitCode of [124, 1, 129]) {
    const result = await scanOsv(await context(envelope(), snapshot.files, exitCode));
    expect(result.findings).toEqual([]);
    expect(result.coverage[0]?.status).toBe("failed");
  }
});
it("preserves diagnostic coverage loss even when exit 1 contains vulnerabilities", async () => {
  const raw = envelope();
  raw.diagnostics = true;
  expect((await scanOsv(await context(raw))).coverage[0]?.status).toBe("degraded");
});
it("rejects another engine version, untrusted source path, malformed advisory and mismatched affected package", async () => {
  const stale = envelope();
  stale.scannerVersion = "2.0.0";
  expect((await scanOsv(await context(stale))).coverage[0]?.status).toBe("failed");
  for (const path of [
    "/etc/passwd",
    "/work/snapshot/../package-lock.json",
    "/work/snapshot/unlisted/package-lock.json",
  ]) {
    const raw = official();
    member(raw.results).source.path = path;
    const result = await scanOsv(await context(envelope(raw)));
    expect(result.findings).toEqual([]);
    expect(result.coverage[0]?.status).not.toBe("checked");
  }
  const raw = official();
  member(member(member(member(raw.results).packages).vulnerabilities).affected).package.name =
    "other";
  const result = await scanOsv(await context(envelope(raw)));
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]?.status).toBe("degraded");
});
it("pins service config, explicit lockfile extractors and disables target resolution/call analysis", () => {
  const args = guest.osvCommand();
  expect(args).toEqual(
    expect.arrayContaining([
      "--config=/opt/vibeshield/osv.toml",
      "--no-ignore",
      "--no-call-analysis=all",
      "--no-resolve",
      "--all-packages",
      "--all-vulns",
      "--experimental-no-default-plugins",
      "--format=json",
      "--output-file=/work/.vibeshield/osv-raw.json",
    ]),
  );
  expect(args.filter((x: string) => x.startsWith("--experimental-plugins="))).toEqual([
    "--experimental-plugins=javascript/packagelockjson,javascript/pnpmlock,javascript/yarnlock,javascript/bunlock",
  ]);
});
it("sanitizes official output without source content or fabricated data revision", async () => {
  const raw = official();
  Object.assign(member(member(member(raw.results).packages).vulnerabilities), {
    details: secret,
    references: [{ url: secret }],
  });
  const clean = guest.sanitizeOsv(raw);
  expect(JSON.stringify(clean)).not.toContain(secret);
  expect((await scanOsv(await context(envelope(clean)))).findings[0]?.dependency?.version).toBe(
    "4.17.20",
  );
  expect(envelope(clean).advisoryData).not.toHaveProperty("revision");
});
it("keeps the manifest range unchanged while fixture installed versions differ", async () => {
  const vulnerable = JSON.parse(
    await readFile("tests/fixtures/scanners/dependencies/vulnerable/package-lock.json", "utf8"),
  );
  const fixed = JSON.parse(
    await readFile("tests/fixtures/scanners/dependencies/fixed/package-lock.json", "utf8"),
  );
  expect(vulnerable.packages[""].devDependencies.lodash).toBe("^4.17.0");
  expect(fixed.packages[""].devDependencies.lodash).toBe("^4.17.0");
  expect(vulnerable.packages["node_modules/lodash"].version).toBe("4.17.20");
  expect(fixed.packages["node_modules/lodash"].version).toBe("4.18.0");
});
it("exposes actual OSV retrieval provenance without inventing a source revision", async () => {
  const ctx = await context();
  expect(await readOsvAdvisoryData(ctx.session)).toEqual({
    source: "OSV",
    retrievedAt: "2026-09-07T12:00:00.000Z",
    stale: false,
  });
  const failed = await context(envelope(official(), 129));
  expect(await readOsvAdvisoryData(failed.session)).toBeUndefined();
});
it("retains aliases carried only by an official advisory group through guest sanitation", async () => {
  const raw = official();
  member(member(member(raw.results).packages).groups).aliases.push("GHSA-group-only-alias");
  const result = await scanOsv(await context(envelope(guest.sanitizeOsv(raw))));
  expect(result.findings[0]?.dependency?.advisoryIds).toContain("GHSA-group-only-alias");
});
it("does not call an exit-1 report clean when official advisory records are missing", async () => {
  const raw = official();
  Object.assign(member(member(raw.results).packages), {
    vulnerabilities: undefined,
    groups: undefined,
  });
  const result = await scanOsv(await context(envelope(raw, 1)));
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]?.status).toBe("degraded");
});
it("does not report advisory retrieval from a malformed official result", async () => {
  const ctx = await context(envelope(null, 0));
  expect(await readOsvAdvisoryData(ctx.session)).toBeUndefined();
});

async function workspaceScan(
  lockfile: string,
  configs: Record<string, unknown>,
  members = ["packages/app/package.json"],
) {
  const files = [...new Set([lockfile, ...Object.keys(configs), ...members])];
  const raw = official();
  member(raw.results).source.path = `/work/snapshot/${lockfile}`;
  member(member(raw.results).packages).package.version = "4.18.0";
  member(member(raw.results).packages).vulnerabilities = [];
  const data = envelope(raw, 0);
  data.workspaceMembers = guest.workspaceMembers(files, configs);
  return scanOsv(await context(data, files));
}
it.each([
  { lockfile: "yarn.lock", configs: { "package.json": { workspaces: ["packages/app"] } } },
  { lockfile: "package-lock.json", configs: { "package.json": { workspaces: ["packages/*"] } } },
  { lockfile: "bun.lock", configs: { "package.json": { workspaces: ["packages/**/app"] } } },
  {
    lockfile: "yarn.lock",
    configs: { "package.json": { workspaces: { packages: ["packages/*"] } } },
  },
  {
    lockfile: "pnpm-lock.yaml",
    configs: { "package.json": {}, "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n" },
  },
])("uses $lockfile only for declared workspace members", async ({ lockfile, configs }) => {
  const result = await workspaceScan(lockfile, configs);
  expect(result.coverage).toEqual([expect.objectContaining({ area: lockfile, status: "checked" })]);
  expect(buildReport({ ...makeReportInput([result]), policy: defaultPolicy }).incomplete).toBe(
    false,
  );
});
it("keeps an undeclared nested project uncovered despite a scanned ancestor lockfile", async () => {
  const result = await workspaceScan(
    "yarn.lock",
    { "package.json": { workspaces: ["packages/*"] } },
    ["packages/app/package.json", "independent/package.json", "packages/app/example/package.json"],
  );
  expect(result.coverage.filter((x) => x.status === "skipped").map((x) => x.area)).toEqual([
    "independent/package.json",
    "packages/app/example/package.json",
  ]);
  expect(buildReport({ ...makeReportInput([result]), policy: defaultPolicy }).incomplete).toBe(
    true,
  );
});
it.each([
  {},
  { workspaces: [] },
  { workspaces: ["elsewhere/*"] },
  { workspaces: ["/packages/*"] },
  { workspaces: ["../packages/*"] },
  { workspaces: ["packages/{app,other}"] },
  { workspaces: ["packages/*", null] },
  { workspaces: ["packages/**", "!packages/app"] },
])("does not infer workspace membership from an ancestor lockfile or unsupported declarations %j", async (config) => {
  const result = await workspaceScan("yarn.lock", { "package.json": config });
  expect(result.coverage).toContainEqual(
    expect.objectContaining({
      area: "packages/app/package.json",
      status: "skipped",
      applicable: true,
    }),
  );
});
it("requires pnpm workspace config rather than package.json workspaces", async () => {
  const result = await workspaceScan("pnpm-lock.yaml", {
    "package.json": { workspaces: ["packages/*"] },
  });
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "packages/app/package.json", status: "skipped" }),
  );
});
it("matches relative workspace globs within their own root and honors pnpm exclusions", async () => {
  const result = await workspaceScan(
    "frontend/pnpm-lock.yaml",
    {
      "frontend/package.json": {},
      "frontend/pnpm-workspace.yaml": "packages:\n  - 'packages/**'\n  - '!packages/private/**'\n",
    },
    [
      "frontend/packages/app/package.json",
      "frontend/packages/private/app/package.json",
      "packages/app/package.json",
    ],
  );
  expect(result.coverage.filter((x) => x.status === "skipped").map((x) => x.area)).toEqual([
    "frontend/packages/private/app/package.json",
    "packages/app/package.json",
  ]);
});
it("does not let unlisted, sibling or unscanned workspace claims hide missing lockfiles", async () => {
  for (const pair of [
    { manifest: "packages/app/package.json", lockfile: "unlisted/yarn.lock" },
    { manifest: "packages/app/package.json", lockfile: "other/yarn.lock" },
    { manifest: "../package.json", lockfile: "yarn.lock" },
  ]) {
    const data = envelope(official(), 0);
    data.workspaceMembers = [pair];
    const result = await scanOsv(
      await context(data, [
        "yarn.lock",
        "other/yarn.lock",
        "package.json",
        "packages/app/package.json",
      ]),
    );
    expect(
      result.coverage.some(
        (x) =>
          x.status === "failed" ||
          (x.area === "packages/app/package.json" && x.status === "skipped"),
      ),
    ).toBe(true);
  }
});
it("keeps a declared member uncovered when its enumerated root lockfile is omitted", async () => {
  const files = ["yarn.lock", "package.json", "packages/app/package.json"];
  const data = envelope({ results: [] }, 0);
  data.workspaceMembers = guest.workspaceMembers(files, {
    "package.json": { workspaces: ["packages/*"] },
  });
  const result = await scanOsv(await context(data, files));
  expect(result.coverage).toEqual([
    expect.objectContaining({ area: "yarn.lock", status: "degraded" }),
    expect.objectContaining({ area: "packages/app/package.json", status: "skipped" }),
  ]);
});
it.each([
  "packages: ['packages/*']\n",
  "packages:\n  - 'packages/*'\npackages:\n  - elsewhere/*\n",
  "packages:\n  - 'packages/*'\n  - *unknown\n",
  "packages:\n  - 'packages/*'\n    nested: invalid\n",
  "packages:\n  - 'packages/*'\n\"packages\": []\n",
  "packages:\n  - 'packages/*'\n---\npackages: []\n",
])("keeps ambiguous or unsupported pnpm declarations uncovered %j", async (yaml) => {
  const result = await workspaceScan("pnpm-lock.yaml", {
    "package.json": {},
    "pnpm-workspace.yaml": yaml,
  });
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "packages/app/package.json", status: "skipped" }),
  );
});
