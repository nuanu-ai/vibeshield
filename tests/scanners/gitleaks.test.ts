import { mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { FakeSandboxRuntime } from "../../src/adapters/fake-sandbox.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { scanGitleaks } from "../../src/scan/scanners/gitleaks.js";
import { readScannerJson } from "../../src/scan/scanners/shared.js";

const modulePath = "../../toolchain/export-results.mjs";
const guest = await import(modulePath);
const head = "a".repeat(40),
  old = "b".repeat(40);
const snapshot: Snapshot = {
  url: "https://github.com/a/b",
  commit: head,
  files: ["app.ts"],
  languages: ["TypeScript"],
  history: { commits: 2, truncated: false },
  oversized: 0,
};
const record = { ruleId: "github-pat", path: "app.ts", line: 7, fingerprint: "c".repeat(64) };
const raw = {
  RuleID: "github-pat",
  File: "app.ts",
  StartLine: 7,
  Commit: head,
  Fingerprint: `${head}:app.ts:github-pat:7`,
  Secret: "synthetic-secret-do-not-export",
  Match: "synthetic-match-do-not-export",
  Description: "synthetic-secret-do-not-export",
};
const dirs: string[] = [];
afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});
async function context(
  current: unknown = [],
  history: unknown = [],
  exitCode = 0,
  truncated = false,
) {
  const runtime = new FakeSandboxRuntime({
    exec: (argv) => ({
      exitCode: argv.includes("gitleaks") ? exitCode : 0,
      stdout: "synthetic-diagnostics-not-json",
      stderr: "synthetic-diagnostics-not-json",
    }),
  });
  const session = await runtime.create({ name: "gitleaks", imageTag: "fixture" });
  const currentSnapshot = { ...snapshot, history: { commits: 2, truncated } };
  await session.uploadBytes(
    "/work/.vibeshield/exports/snapshot.json",
    Buffer.from(
      JSON.stringify({
        snapshot: currentSnapshot,
        entries: [{ path: "app.ts", size: 10, kind: "file" }],
        fetchedCommits: [head, old],
      }),
    ),
  );
  for (const [mode, data] of [
    ["current", current],
    ["history", history],
  ] as const) {
    await session.uploadBytes(
      `/work/.vibeshield/exports/gitleaks-${mode}.json`,
      Buffer.from(typeof data === "string" ? data : JSON.stringify(data)),
    );
  }
  return { session, snapshot: currentSnapshot, signal: new AbortController().signal };
}
it("preserves history-only commit and path and requests credential rotation", async () => {
  const result = await scanGitleaks(
    await context([], [{ ...record, path: "deleted.env", commit: old }]),
  );
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]?.locations).toEqual([{ path: "deleted.env", line: 7, commit: old }]);
  expect(result.findings[0]?.remediationKey).toBe("secret-rotation");
});
it("combines duplicate exposures while preserving historical locations", async () => {
  const result = await scanGitleaks(await context([record], [{ ...record, commit: old }]));
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]?.locations).toEqual([
    { path: "app.ts", line: 7 },
    { path: "app.ts", line: 7, commit: old },
  ]);
});
it("accepts equivalent Snapshot fields regardless of object property order", async () => {
  const ctx = await context([record]);
  ctx.snapshot = {
    history: ctx.snapshot.history,
    oversized: ctx.snapshot.oversized,
    languages: ctx.snapshot.languages,
    files: ctx.snapshot.files,
    commit: ctx.snapshot.commit,
    url: ctx.snapshot.url,
  };
  expect((await scanGitleaks(ctx)).findings).toHaveLength(1);
});
it.each([
  "../escape",
  "/etc/passwd",
  "C:/escape",
  "a\\b",
  "a/../b",
  "a//b",
  "a\nname",
  "node_modules/ignored.ts",
])("rejects unsafe history path %s", async (path) => {
  expect(
    (await scanGitleaks(await context([], [{ ...record, path, commit: old }]))).coverage,
  ).toContainEqual(expect.objectContaining({ area: "history", status: "failed" }));
});
it("rejects a current path outside the manifest and an unfetched history commit", async () => {
  const result = await scanGitleaks(
    await context([{ ...record, path: "link.ts" }], [{ ...record, commit: "d".repeat(40) }]),
  );
  expect(result.findings).toEqual([]);
  expect(result.coverage.every((x) => x.status === "failed")).toBe(true);
});
it.each([
  "{",
  "{}",
  "",
  `[]${" ".repeat(10 * 1024 * 1024)}`,
])("reports malformed, missing or oversized export as failed", async (data) => {
  const result = await scanGitleaks(await context(data, []));
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "current", status: "failed" }),
  );
});
it("reports nonzero scanner exits as failure even with valid exports", async () => {
  const result = await scanGitleaks(await context([record], [{ ...record, commit: old }], 2));
  expect(result.findings).toEqual([]);
  expect(result.coverage.every((x) => x.status === "failed")).toBe(true);
  expect(JSON.stringify(result)).not.toContain("synthetic-diagnostics");
});
it("marks limited history degraded while preserving checked current coverage", async () => {
  const result = await scanGitleaks(await context([], [], 0, true));
  expect(result.coverage).toContainEqual(
    expect.objectContaining({
      area: "history",
      status: "degraded",
      reason: expect.stringMatching(/2.*commit/),
    }),
  );
  expect(result.coverage).toContainEqual(
    expect.objectContaining({ area: "current", status: "checked" }),
  );
});
it("rejects secret-bearing exports and never reflects scanner metadata", async () => {
  const result = await scanGitleaks(
    await context([{ ...record, Secret: "synthetic-secret-do-not-export" }], []),
  );
  expect(result.findings).toEqual([]);
  expect(result.coverage[0]?.status).toBe("failed");
  expect(JSON.stringify(result)).not.toContain("synthetic-secret-do-not-export");
});
it("only reads owned export paths and rejects malformed JSON without echoing it", async () => {
  const ctx = await context();
  await expect(readScannerJson(ctx.session, "/work/repository/report.json")).rejects.toThrow(
    /export/i,
  );
  await ctx.session.uploadBytes(
    "/work/.vibeshield/exports/osv.json",
    Buffer.from("synthetic-secret-do-not-export"),
  );
  await expect(readScannerJson(ctx.session, "/work/.vibeshield/exports/osv.json")).rejects.toThrow(
    /^Invalid scanner export$/,
  );
});
it("guest export removes Secret, Match and arbitrary metadata before host transfer", () => {
  const output = guest.sanitizeGitleaks(
    [raw],
    { files: ["app.ts"], fetchedCommits: [head, old] },
    "history",
  );
  expect(output).toEqual([
    {
      ruleId: "github-pat",
      path: "app.ts",
      line: 7,
      commit: head,
      fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
    },
  ]);
  expect(JSON.stringify(output)).not.toMatch(/synthetic|Secret|Match|Description/);
});
it.each([
  ["current", { File: "link.ts" }],
  ["history", { File: "../outside" }],
  ["history", { Commit: "d".repeat(40) }],
])("guest rejects invalid %s raw locations %j", (mode, change) => {
  expect(() =>
    guest.sanitizeGitleaks(
      [{ ...raw, ...change }],
      { files: ["app.ts"], fetchedCommits: [head, old] },
      mode,
    ),
  ).toThrow(/Invalid scanner export/);
});
it("guest suppresses generated-file matches and preserves a deleted history path", () => {
  const result = guest.sanitizeGitleaks(
    [
      { ...raw, File: "node_modules/ignored.ts" },
      { ...raw, File: "removed.env", Commit: old },
    ],
    { files: ["app.ts"], fetchedCommits: [head, old] },
    "history",
  );
  expect(result).toHaveLength(1);
  expect(result[0]).toMatchObject({ path: "removed.env", commit: old });
});
it("guest rejects malformed and missing raw reports without reflecting their bytes", async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "vs-export-malformed-")));
  dirs.push(dir);
  await writeFile(join(dir, "raw.json"), "synthetic-secret-do-not-export", { mode: 0o600 });
  expect(() => guest.readBoundedJson(join(dir, "raw.json"))).toThrow(/^Invalid scanner export$/);
  expect(() => guest.readBoundedJson(join(dir, "missing.json"))).toThrow(
    /^Invalid scanner export$/,
  );
});
it("guest rejects symlink exports and bounds size before reading raw reports", async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "vs-export-fixture-")));
  dirs.push(dir);
  await writeFile(join(dir, "raw.json"), "[]", { mode: 0o600 });
  await symlink(join(dir, "raw.json"), join(dir, "link.json"));
  expect(() => guest.readBoundedJson(join(dir, "link.json"))).toThrow(/Invalid scanner export/);
  await writeFile(join(dir, "big.json"), `[]${" ".repeat(10 * 1024 * 1024)}`, { mode: 0o600 });
  expect(() => guest.readBoundedJson(join(dir, "big.json"))).toThrow(/Invalid scanner export/);
  expect(guest.readBoundedJson(join(dir, "raw.json"))).toEqual([]);
});
