import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";
import { FakeSandboxRuntime } from "../../src/adapters/fake-sandbox.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { scanZizmor } from "../../src/scan/scanners/zizmor.js";
import { makeFinding, makeReportInput } from "../support/findings.js";

const raw = JSON.parse(
  await readFile(new URL("../fixtures/scanners/workflows/zizmor.json", import.meta.url), "utf8"),
);
const guestPath = "../../toolchain/zizmor.mjs";
const guest = await import(guestPath);
const snapshot: Snapshot = {
  url: "https://github.com/fixture/workflows",
  commit: "a".repeat(40),
  files: [".github/workflows/vulnerable.yml", ".github/workflows/fixed.yml"],
  languages: [],
  history: { commits: 1, truncated: false },
};
const secret = "synthetic-target-text-never-export";
function output() {
  return {
    version: "1.30.0",
    offline: true,
    warnings: false,
    selectedAudits: ["template-injection"],
    files: [...snapshot.files],
    findings: structuredClone(raw),
  };
}
async function context(value: unknown = output(), exitCode = 0, verifyCode = 0) {
  const runtime = new FakeSandboxRuntime({
    exec: (argv) => ({
      exitCode: argv.includes("/usr/local/bin/vibeshield-zizmor") ? exitCode : verifyCode,
      stdout: secret,
      stderr: secret,
    }),
  });
  const session = await runtime.create({ name: "zizmor-test", imageTag: "fixture" });
  await session.uploadBytes(
    "/work/.vibeshield/exports/zizmor.json",
    Buffer.from(typeof value === "string" ? value : JSON.stringify(value)),
  );
  return { session, snapshot, signal: new AbortController().signal };
}
const report = (result: Awaited<ReturnType<typeof scanZizmor>>) =>
  buildReport({ ...makeReportInput([result]), policy: defaultPolicy });

it("publishes unsafe workflow input but not routine pinning advice", async () => {
  const result = await scanZizmor(await context());
  expect(report(result).issues).toHaveLength(1);
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]).toMatchObject({
    scanner: "zizmor",
    ruleId: "template-injection",
    category: "workflow",
    severity: "high",
    confidence: "high",
    locations: [{ path: ".github/workflows/vulnerable.yml", line: 12 }],
    remediationKey: "workflow-input",
  });
  expect(report(result).issues[0]?.remediation).toContain("environment variable");
  expect(report(result).issues[0]?.verification).toContain("workflow");
  expect(result.findings[0]?.evidence).toContain(
    "https://docs.zizmor.sh/audits/#template-injection",
  );
});
it("never publishes generic trigger, permission, or hash pinning advice by title or wildcard", () => {
  for (const ruleId of [
    "dangerous-workflow-permissions",
    "dangerous-triggers",
    "excessive-permissions",
    "unpinned-uses",
    "*",
  ])
    expect(
      report({
        findings: [
          makeFinding({
            scanner: "zizmor",
            category: "workflow",
            ruleId,
            remediationKey: "workflow-privilege",
          }),
        ],
        coverage: [],
      }).issues,
    ).toEqual([]);
});
it("skips absent workflows without engine execution", async () => {
  const ctx = await context();
  const result = await scanZizmor({
    ...ctx,
    snapshot: { ...snapshot, files: ["app.ts", "example.yml"] },
  });
  expect(result).toMatchObject({
    findings: [],
    coverage: [{ scanner: "zizmor", applicable: false, status: "skipped" }],
  });
  expect(ctx.session.invocations).toEqual([]);
});
it("reports selected checks completed on a valid empty result and discloses offline unavailable audits", async () => {
  const value = output();
  value.findings = [];
  const result = await scanZizmor(await context(value));
  expect(result.findings).toEqual([]);
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "workflows", status: "checked", applicable: true }),
  );
  const offline = result.coverage.find((c) => c.area === "online-audits");
  expect(offline).toMatchObject({ status: "skipped", applicable: true });
  for (const id of [
    "impostor-commit",
    "ref-confusion",
    "stale-action-refs",
    "ref-version-mismatch",
    "known-vulnerable-actions",
  ])
    expect(offline?.reason).toContain(id);
  expect(report(result).incomplete).toBe(true);
});
it("does not honor the repository annotation's ignored marker in exported findings", async () => {
  expect(report(await scanZizmor(await context())).issues).toHaveLength(1);
});
it("makes engine warnings and unsupported checkout combinations explicit without exposing diagnostics", async () => {
  const value = output();
  value.warnings = true;
  const result = await scanZizmor(await context(value));
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "workflows", status: "degraded" }),
  );
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "untrusted-checkout", status: "skipped", applicable: true }),
  );
  expect(report(result).issues).toHaveLength(1);
  expect(JSON.stringify(result)).not.toContain(secret);
});
it.each([
  "Low",
  "Medium",
  "Informational",
  "Unknown",
])("does not promote %s severity", async (severity) => {
  const value = output();
  value.findings[1].determinations.severity = severity;
  expect(report(await scanZizmor(await context(value))).issues).toEqual([]);
});
it.each([
  "Low",
  "Medium",
  "Unknown",
])("requires high confidence, observed %s", async (confidence) => {
  const value = output();
  value.findings[1].determinations.confidence = confidence;
  expect(report(await scanZizmor(await context(value))).issues).toEqual([]);
});
it.each([
  "{",
  "null",
  "{}",
  " ".repeat(8 * 1024 * 1024 + 1),
])("rejects malformed or oversized bounded export %#", async (value) => {
  const result = await scanZizmor(await context(value));
  expect(result).toMatchObject({
    findings: [],
    coverage: [expect.objectContaining({ status: "failed" })],
  });
  expect(JSON.stringify(result)).not.toContain(secret);
});
it.each([
  1, 2, 14, 124, 137,
])("fails guest exit %s without trusting leftover JSON", async (code) => {
  const result = await scanZizmor(await context(output(), code));
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]?.status).toBe("failed");
});
it("rejects a failed guest file ownership, symlink, or bounds verification", async () => {
  expect((await scanZizmor(await context(output(), 0, 1))).coverage[0]?.status).toBe("failed");
});
it("rejects an oversized otherwise-valid JSON export before normalization", async () => {
  const value = { ...output(), padding: "x".repeat(8 * 1024 * 1024) };
  const result = await scanZizmor(await context(value));
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]?.status).toBe("failed");
});
it.each([
  "../escape.yml",
  "/etc/passwd",
  "/work/snapshot/dir/../bad.yml",
  "/work/snapshot/.github/workflows/other.yml",
  "/work/snapshot/.github\\workflows\\vulnerable.yml",
])("rejects unsafe or non-snapshot finding path %s", async (path) => {
  const value = output();
  value.findings[1].locations[0].path = path;
  const result = await scanZizmor(await context(value));
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]?.status).toBe("failed");
});
it.each([-1, 1.5, null])("rejects invalid zero-based source row %s", async (row) => {
  const value = output();
  value.findings[1].locations[0].row = row;
  expect((await scanZizmor(await context(value))).coverage[0]?.status).toBe("failed");
});
it("rejects missing source evidence, reference, engine version, selected audits, offline guarantee, and unscanned workflow", async () => {
  for (const change of [
    (v: ReturnType<typeof output>) => {
      v.findings[1].locations = [];
    },
    (v: ReturnType<typeof output>) => {
      v.findings[1].url = "https://attacker.invalid/";
    },
    (v: ReturnType<typeof output>) => {
      v.version = "1.31.0";
    },
    (v: ReturnType<typeof output>) => {
      v.selectedAudits = [];
    },
    (v: ReturnType<typeof output>) => {
      v.offline = false;
    },
    (v: ReturnType<typeof output>) => {
      v.files = [];
    },
  ]) {
    const value = output();
    change(value);
    const result = await scanZizmor(await context(value));
    expect(result.findings).toEqual([]);
    expect(result.coverage[0]?.status).toBe("failed");
  }
});
it("propagates cancellation before and after execution", async () => {
  const ctx = await context();
  await expect(
    scanZizmor({ ...ctx, signal: AbortSignal.abort(new Error("cancelled")) }),
  ).rejects.toThrow("cancelled");
  const controller = new AbortController();
  const original = ctx.session.exec.bind(ctx.session);
  ctx.session.exec = async (...args) => {
    const result = await original(...args);
    controller.abort(new Error("cancelled"));
    return result;
  };
  await expect(scanZizmor({ ...ctx, signal: controller.signal })).rejects.toThrow("cancelled");
});
it("exports only engine identifiers, determinations, and primary coordinates without target snippets or annotations", () => {
  const finding = {
    ident: "template-injection",
    desc: secret,
    url: "https://docs.zizmor.sh/audits/#template-injection",
    determinations: { severity: "High", confidence: "High" },
    ignored: true,
    fixes: [{ title: secret }],
    locations: [
      {
        symbolic: {
          kind: "Primary",
          key: { Local: { verbatim_path: "/work/snapshot/.github/workflows/vulnerable.yml" } },
          annotation: secret,
        },
        concrete: {
          location: { start_point: { row: 11 }, end_point: { row: 11 } },
          feature: secret,
          comments: [secret],
        },
      },
      {
        symbolic: { kind: "Hidden", key: { Local: { verbatim_path: secret } } },
        concrete: { feature: secret },
      },
    ],
  };
  const clean = guest.sanitizeZizmor([finding]);
  expect(clean).toEqual([
    {
      ident: "template-injection",
      url: "https://docs.zizmor.sh/audits/#template-injection",
      determinations: { severity: "High", confidence: "High" },
      locations: [{ path: "/work/snapshot/.github/workflows/vulnerable.yml", row: 11, endRow: 11 }],
    },
  ]);
  expect(JSON.stringify(clean)).not.toContain(secret);
  for (const malformed of [null, {}, [{ ...finding, locations: null }]])
    expect(() => guest.sanitizeZizmor(malformed)).toThrow();
});
it("requests strict offline parsing, ignores repository annotations and reads explicit snapshot files", () => {
  const argv = guest.zizmorCommand([".github/workflows/vulnerable.yml"]);
  for (const flag of [
    "--offline",
    "--format=json-v1",
    "--config=/opt/vibeshield/zizmor.json",
    "--no-ignores",
    "--strict-collection",
    "--no-exit-codes",
    "/work/snapshot/.github/workflows/vulnerable.yml",
  ])
    expect(argv).toContain(flag);
});
