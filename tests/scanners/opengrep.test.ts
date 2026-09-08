import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { verifyRules } from "../../scripts/prepare-rules.js";
import { FakeSandboxRuntime } from "../../src/adapters/fake-sandbox.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { hasRemediationTemplate } from "../../src/scan/remediation.js";
import { buildReport } from "../../src/scan/report.js";
import { parseOpengrepSarif, scanOpengrep } from "../../src/scan/scanners/opengrep.js";
import { makeFinding, makeReportInput } from "../support/findings.js";

const guestPath = "../../toolchain/opengrep.mjs";
const guest = await import(guestPath);
const ssrf = "rules_lgpl_javascript_ssrf_rule-node-ssrf";
const shelljs = "rules_lgpl_javascript_exec_rule-shelljs-os-command-exec";
const snapshot: Snapshot = {
  url: "https://github.com/fixture/code",
  commit: "a".repeat(40),
  files: ["app.ts"],
  languages: ["TypeScript"],
  history: { commits: 1, truncated: false },
  oversized: 0,
};
const secret = "synthetic-target-content-never-export";
function location(line = 5, uri = "/work/snapshot/app.ts") {
  return {
    physicalLocation: {
      artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
      region: { startLine: line, snippet: { text: secret } },
    },
  };
}
function result(ruleId = ssrf, flow = true) {
  return {
    ruleId,
    level: "error",
    message: { text: secret },
    locations: [location()],
    ...(flow
      ? {
          codeFlows: [
            {
              message: { text: secret },
              threadFlows: [
                {
                  locations: [
                    { location: location(2) },
                    { location: location(4) },
                    { location: location(5) },
                  ],
                },
              ],
            },
          ],
        }
      : {}),
  };
}
function sarif(results: unknown[] = [result()], securitySeverity: unknown = "HIGH") {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Opengrep OSS",
            semanticVersion: "1.25.0",
            rules: [
              {
                id: ssrf,
                name: ssrf,
                shortDescription: { text: "Server-side request forgery (SSRF)" },
                fullDescription: { text: "User-controlled request URL reaches a network client." },
                help: { text: "Use approved destinations." },
                defaultConfiguration: { level: "error" },
                properties: {
                  "security-severity": securitySeverity,
                  precision: "very-high",
                  tags: ["CWE-918", "security"],
                },
              },
              {
                id: shelljs,
                shortDescription: { text: "OS command injection" },
                properties: {
                  "security-severity": "CRITICAL",
                  precision: "very-high",
                  tags: ["CWE-78"],
                },
              },
              ...[
                "rules_lgpl_javascript_database_rule-node-sqli-injection",
                "rules_lgpl_javascript_traversal_rule-express-lfr",
                "rules_lgpl_javascript_eval_rule-node-deserialize",
                "rules_lgpl_javascript_jwt_rule-node-jwt-none-algorithm",
              ].map((id) => ({
                id,
                properties: {
                  "security-severity": "CRITICAL",
                  precision: "very-high",
                  tags: ["security"],
                },
              })),
            ] satisfies [unknown, ...unknown[]],
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            toolExecutionNotifications: [] as unknown[],
            toolConfigurationNotifications: [] as unknown[],
          },
        ] satisfies [unknown],
        results,
      },
    ] satisfies [unknown],
  };
}
async function context(value: unknown, exitCode = 0) {
  const runtime = new FakeSandboxRuntime({
    exec: (argv) => ({
      exitCode: argv.includes("/usr/local/bin/vibeshield-opengrep") ? exitCode : 0,
      stdout: secret,
      stderr: secret,
    }),
  });
  const session = await runtime.create({ name: "opengrep-test", imageTag: "fixture" });
  await session.uploadBytes(
    "/work/.vibeshield/exports/opengrep.json",
    Buffer.from(typeof value === "string" ? value : JSON.stringify(value)),
  );
  return { session, snapshot, signal: new AbortController().signal };
}

it.each([
  { files: ["app.py"], languages: ["Python"] },
  { files: ["README.md"], languages: [] },
  { files: ["app.py"], languages: ["JavaScript"] },
  { files: [], languages: ["TypeScript"] },
])("skips unsupported-only snapshot $files without executing or reading a scanner", async (source) => {
  const ctx = await context(sarif([]));
  const unsupported = { ...snapshot, ...source };
  const expected = {
    findings: [],
    coverage: [expect.objectContaining({ status: "skipped", applicable: false })],
  };
  expect(parseOpengrepSarif(sarif([]), unsupported)).toEqual(expected);
  expect(await scanOpengrep({ ...ctx, snapshot: unsupported })).toEqual(expected);
  expect(ctx.session.invocations).toEqual([]);
});
it.each([
  "app.js",
  "app.jsx",
  "app.mjs",
  "app.ts",
  "app.tsx",
])("keeps mixed supported %s and Python source applicable, preserving warnings", async (path) => {
  const mixed = {
    ...snapshot,
    files: ["app.py", path],
    languages: ["Python", "JavaScript", "TypeScript"],
  };
  const ctx = await context(sarif([]));
  expect((await scanOpengrep({ ...ctx, snapshot: mixed })).coverage[0]).toMatchObject({
    status: "checked",
    applicable: true,
  });
  expect(ctx.session.invocations.length).toBeGreaterThan(0);
  const warning = sarif([]);
  warning.runs[0].invocations[0].toolExecutionNotifications = [{ level: "warning" }];
  expect(parseOpengrepSarif(warning, mixed).coverage[0]).toMatchObject({
    status: "degraded",
    applicable: true,
  });
});

it("preserves a selected taint source, sink and path without target snippets", () => {
  const parsed = parseOpengrepSarif(sarif(), snapshot);
  expect(parsed.findings).toHaveLength(1);
  expect(parsed.findings[0]).toMatchObject({
    ruleId: ssrf,
    severity: "high",
    confidence: "high",
    remediationKey: "path-url-validation",
    locations: [{ path: "app.ts", line: 5 }],
    code: {
      mode: "taint",
      flows: [
        [
          { path: "app.ts", line: 2 },
          { path: "app.ts", line: 4 },
          { path: "app.ts", line: 5 },
        ],
      ],
      rule: {
        description: "User-controlled request URL reaches a network client.",
        tags: ["CWE-918", "security"],
        securitySeverity: "HIGH",
      },
    },
  });
  expect(parsed.findings[0]?.evidence).toMatch(/flow:.*app.ts:2.*app.ts:4.*app.ts:5/);
  expect(JSON.stringify(parsed)).not.toContain(secret);
  expect(buildReport({ ...makeReportInput([parsed]), policy: defaultPolicy }).issues).toHaveLength(
    1,
  );
});
it("fails SARIF that omits selected rule definitions or claims another engine version", () => {
  const missing = sarif([]);
  missing.runs[0]?.tool.driver.rules.pop();
  expect(parseOpengrepSarif(missing, snapshot).coverage[0]?.status).toBe("failed");
  const stale = sarif([]);
  Object.assign(stale.runs[0]?.tool.driver ?? {}, { semanticVersion: "1.0.0" });
  expect(parseOpengrepSarif(stale, snapshot).coverage[0]?.status).toBe("failed");
});
it("publishes the exact validated SSRF ID with flow and matching remediation", () => {
  const parsed = {
    findings: [
      makeFinding({
        scanner: "opengrep",
        ruleId: ssrf,
        category: "code",
        severity: "high",
        confidence: "high",
        remediationKey: "path-url-validation",
        evidence: "flow: app.ts:2 -> app.ts:5",
      }),
    ],
    coverage: [],
  };
  expect(buildReport({ ...makeReportInput([parsed]), policy: defaultPolicy }).issues).toHaveLength(
    1,
  );
});
it("does not fabricate taint proof for the contextual ShellJS rule", () => {
  const parsed = parseOpengrepSarif(sarif([result(shelljs, false)]), snapshot);
  expect(parsed.findings[0]).toMatchObject({
    severity: "critical",
    confidence: "medium",
    code: { mode: "search", flows: [] },
  });
  expect(parsed.findings[0]?.evidence).not.toMatch(/flow:/);
  expect(buildReport({ ...makeReportInput([parsed]), policy: defaultPolicy }).issues).toEqual([]);
});
it.each([
  ["MEDIUM", "medium"],
  ["LOW", "low"],
  ["9.3", "critical"],
  ["7.1", "high"],
  ["4.0", "medium"],
  ["2.0", "low"],
  [undefined, "unknown"],
  ["bogus", "unknown"],
  ["11", "unknown"],
])("uses metadata severity %s instead of SARIF error level", (input, expected) => {
  const raw = sarif();
  raw.runs[0].tool.driver.rules[0].properties["security-severity"] = input;
  expect(parseOpengrepSarif(raw, snapshot).findings[0]?.severity).toBe(expected);
});
it.each(
  [
    [],
    [location(0)],
    [location(5, "../escape.ts")],
    [location(5, "/etc/passwd")],
    [location(5, "other.ts")],
  ].map((locations) => ({ locations })),
)("degrades coverage and withholds a result without a current snapshot location $locations", ({
  locations,
}) => {
  const parsed = parseOpengrepSarif(sarif([{ ...result(), locations }]), snapshot);
  expect(parsed.findings).toEqual([]);
  expect(parsed.coverage[0]?.status).toBe("degraded");
});
it("withholds missing or disconnected flow evidence from publication", () => {
  const parsed = parseOpengrepSarif(sarif([result(ssrf, false)]), snapshot);
  expect(parsed.findings[0]?.confidence).toBe("unknown");
  expect(buildReport({ ...makeReportInput([parsed]), policy: defaultPolicy }).issues).toEqual([]);
  const disconnected = result();
  disconnected.codeFlows = [
    {
      message: { text: secret },
      threadFlows: [{ locations: [{ location: location(2) }, { location: location(4) }] }],
    },
  ];
  const invalid = parseOpengrepSarif(sarif([disconnected]), snapshot);
  expect(invalid.coverage[0]?.status).toBe("degraded");
  expect(buildReport({ ...makeReportInput([invalid]), policy: defaultPolicy }).issues).toEqual([]);
});
it.each([
  "toolExecutionNotifications",
  "toolConfigurationNotifications",
] as const)("preserves %s warnings as coverage loss without echoing diagnostics", (field) => {
  const raw = sarif([]);
  raw.runs[0].invocations[0][field] = [
    { level: "warning", message: { text: secret }, descriptor: { id: "ParseError" } },
  ];
  const parsed = parseOpengrepSarif(raw, snapshot);
  expect(parsed.coverage[0]?.status).toBe("degraded");
  expect(JSON.stringify(parsed)).not.toContain(secret);
});
it("marks unsuccessful SARIF invocation as failed", () => {
  const raw = sarif([]);
  raw.runs[0].invocations[0].executionSuccessful = false;
  expect(parseOpengrepSarif(raw, snapshot).coverage[0]?.status).toBe("failed");
});
it("distinguishes a valid empty report from malformed or unknown-rule output", () => {
  expect(parseOpengrepSarif(sarif([]), snapshot).coverage[0]?.status).toBe("checked");
  for (const raw of [
    {},
    { version: "2.1.0", runs: [] },
    sarif([{ ...result(), ruleId: "unselected-rule" }]),
  ]) {
    expect(parseOpengrepSarif(raw, snapshot).coverage[0]?.status).not.toBe("checked");
  }
});
it("uses bounded service exports and refuses nonzero exits without reflecting stdout", async () => {
  expect((await scanOpengrep(await context(sarif()))).findings).toHaveLength(1);
  for (const ctx of [
    await context(sarif(), 2),
    await context("{"),
    await context(`{}${" ".repeat(10 * 1024 * 1024)}`),
  ]) {
    const parsed = await scanOpengrep(ctx);
    expect(parsed.findings).toEqual([]);
    expect(parsed.coverage[0]?.status).toBe("failed");
    expect(JSON.stringify(parsed)).not.toContain(secret);
  }
});
it("guest export removes all target snippets and diagnostics while retaining rule metadata and locations", () => {
  const clean = guest.sanitizeSarif(sarif());
  expect(JSON.stringify(clean)).not.toContain(secret);
  expect(parseOpengrepSarif(clean, snapshot).findings[0]).toMatchObject({
    severity: "high",
    confidence: "high",
  });
});
it("routes scanner settings and ignore configuration to service files", () => {
  const previous = process.env.SEMGREP_SETTINGS_FILE;
  try {
    process.env.SEMGREP_SETTINGS_FILE = "/work/snapshot/poison.yml";
    const env = guest.opengrepEnvironment();
    expect(env.SEMGREP_SETTINGS_FILE).toBe("/opt/vibeshield/opengrep-settings.yml");
    expect(env.SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE).toBe("/opt/vibeshield/opengrep.ignore");
    expect(Object.values(env)).not.toContain("/work/snapshot/poison.yml");
  } finally {
    if (previous === undefined) delete process.env.SEMGREP_SETTINGS_FILE;
    else process.env.SEMGREP_SETTINGS_FILE = previous;
  }
});

const dirs: string[] = [];
afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});
it("verifies frozen rule and fixture hashes and requires an exact-ID remediation policy for every enabled rule", async () => {
  await expect(verifyRules("toolchain/rules")).resolves.toBeUndefined();
  const manifest = JSON.parse(await readFile("toolchain/rules/manifest.json", "utf8"));
  expect(manifest.rules).toHaveLength(6);
  for (const rule of manifest.rules) {
    const policy = defaultPolicy.find(
      (entry) => entry.scanner === "opengrep" && entry.ruleId === rule.id,
    );
    expect(policy?.remediationKey).toBe(rule.remediationKey);
    expect(hasRemediationTemplate(rule.remediationKey)).toBe(true);
  }
});
it("rejects changed rule bytes, fixture bytes and provenance revision", async () => {
  await expect(verifyRules("toolchain/rules")).resolves.toBeUndefined();
  const dir = await mkdtemp(join(tmpdir(), "vs-rules-"));
  dirs.push(dir);
  await cp("toolchain/rules", dir, { recursive: true });
  const manifest = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8"));
  const rule = join(dir, manifest.rules[0].path);
  const original = await readFile(rule);
  await writeFile(rule, Buffer.concat([original, Buffer.from("\n# synthetic byte mutation\n")]));
  await expect(verifyRules(dir)).rejects.toThrow(/rule|integrity|hash/i);
  await writeFile(rule, original);
  const fixture = join(dir, manifest.artifacts[0].path);
  const fixtureBytes = await readFile(fixture);
  await writeFile(
    fixture,
    Buffer.concat([fixtureBytes, Buffer.from("\n// synthetic byte mutation\n")]),
  );
  await expect(verifyRules(dir)).rejects.toThrow(/hash/i);
  await writeFile(fixture, fixtureBytes);
  manifest.revision = "b".repeat(40);
  await writeFile(join(dir, "manifest.json"), JSON.stringify(manifest));
  await expect(verifyRules(dir)).rejects.toThrow(/revision|provenance/i);
});
