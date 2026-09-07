import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { FakeSandboxRuntime } from "../../src/adapters/fake-sandbox.js";
import { validateAcquisition } from "../../src/scan/manifest.js";
import { acquire, parseRepositoryUrl } from "../../src/scan/source.js";

const guestModule = "../../toolchain/acquire.mjs";
const guest = await import(guestModule);
const commit = "a".repeat(40);
const snapshot = {
  url: "https://github.com/Owner/Repo",
  commit,
  files: ["src/app.ts"],
  languages: ["TypeScript"],
  history: { commits: 1, truncated: false },
};
const manifest = {
  snapshot,
  entries: [{ path: "src/app.ts", size: 10, kind: "file" }],
  fetchedCommits: [commit],
};
const dirs: string[] = [];
afterEach(async () => {
  for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true });
});

it.each([
  "http://github.com/a/b",
  "https://github.com/a/b/tree/main",
  "https://github.com@evil.test/a/b",
  "/tmp/repo",
  "https://github.com/a/b?x=1",
  "https://github.com/a/b#x",
  "https://evil.test/a/b",
  "https://user:pass@github.com/a/b",
  "https://github.com:444/a/b",
  "https://github.com/a/..",
  "https://github.com/a/%2e%2e",
  "https://github.com/a%2fb/c",
  "https://github.com/a\\b/c",
  "https://github.com/a/.git",
  "https://github.com/./a/b",
  " https://github.com/a/b",
  "https://github.com/a/b\n",
])("rejects non-root input %s", (url) => {
  expect(() => parseRepositoryUrl(url)).toThrow("Enter a public GitHub repository URL");
  expect(() => guest.parseRepositoryUrl(url)).toThrow("Enter a public GitHub repository URL");
});
it("normalizes the optional git suffix and preserves case", () => {
  expect(parseRepositoryUrl("https://github.com/Owner/Repo.git/")).toBe(
    "https://github.com/Owner/Repo",
  );
  expect(guest.parseRepositoryUrl("https://github.com/Owner/Repo.git/")).toBe(
    "https://github.com/Owner/Repo",
  );
});
it("acquires bounded file metadata without interpreting diagnostic stdout", async () => {
  const runtime = new FakeSandboxRuntime({
    exec: async (argv, session) => {
      if (argv.includes("/usr/local/bin/vibeshield-acquire"))
        await session.uploadBytes(
          "/work/.vibeshield/exports/snapshot.json",
          Buffer.from(JSON.stringify(manifest)),
        );
      return { exitCode: 0, stdout: "this is not JSON", stderr: "" };
    },
  });
  const session = await runtime.create({ name: "source", imageTag: "fixture" });
  expect(await acquire(session, snapshot.url, new AbortController().signal)).toEqual(snapshot);
});
it("rejects failed acquisition without echoing repository diagnostics", async () => {
  const runtime = new FakeSandboxRuntime({
    exec: () => ({ exitCode: 128, stdout: "fixture-private-text", stderr: "fixture-private-text" }),
  });
  const session = await runtime.create({ name: "source", imageTag: "fixture" });
  await expect(acquire(session, snapshot.url, new AbortController().signal)).rejects.toThrow(
    /^Repository acquisition failed$/,
  );
});
it.each([
  { entries: [{ path: "../escape", size: 1, kind: "file" }] },
  { entries: [{ path: "src/app.ts", size: 1, kind: "symlink" }] },
  { entries: [{ path: "src/app.ts", size: 501 * 1024 * 1024, kind: "file" }] },
  { entries: [{ path: "src/app.ts", size: -1, kind: "file" }] },
  { fetchedCommits: ["b".repeat(40)] },
  { snapshot: { ...snapshot, files: ["untracked.ts"] } },
])("rejects unsafe or inconsistent acquisition metadata %j", (change) => {
  expect(() => validateAcquisition({ ...manifest, ...change })).toThrow(/Invalid snapshot/);
});
it("enforces file count and aggregate size before accepting a manifest", () => {
  const entries = Array.from({ length: 50_001 }, (_, i) => ({
    path: `${i}.ts`,
    size: 1,
    kind: "file",
  }));
  expect(() =>
    validateAcquisition({
      ...manifest,
      entries,
      snapshot: { ...snapshot, files: entries.map((x) => x.path) },
    }),
  ).toThrow(/Invalid snapshot/);
  const large = Array.from({ length: 101 }, (_, i) => ({
    path: `${i}.ts`,
    size: 5 * 1024 * 1024,
    kind: "file",
  }));
  expect(() =>
    validateAcquisition({
      ...manifest,
      entries: large,
      snapshot: { ...snapshot, files: large.map((x) => x.path) },
    }),
  ).toThrow(/Invalid snapshot/);
});
it("inventories Git regular files, suppressing symlinks and generated directories", async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "vs-source-fixture-")));
  dirs.push(dir);
  await mkdir(join(dir, "repo"));
  const repo = join(dir, "repo");
  execFileSync("git", ["init", "-q", repo]);
  await writeFile(join(repo, "app.ts"), "export const safe = true;\n");
  await mkdir(join(repo, "node_modules"));
  await writeFile(join(repo, "node_modules", "ignored.ts"), "fixture");
  await symlink("app.ts", join(repo, "link.ts"));
  execFileSync("git", ["-C", repo, "add", "-f", "."]);
  execFileSync("git", [
    "-C",
    repo,
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-qm",
    "fixture",
  ]);
  const result = await guest.inventory(repo, join(dir, "snapshot"), snapshot.url);
  expect(result.snapshot.files).toEqual(["app.ts"]);
  expect(result.snapshot.languages).toEqual(["TypeScript"]);
  expect(result.snapshot.history).toEqual({ commits: 1, truncated: false });
});
it("marks the history cap even when the fetched repository is not shallow", async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), "vs-history-cap-")));
  dirs.push(dir);
  const repo = join(dir, "repo");
  execFileSync("git", ["init", "-q", repo]);
  const input = Array.from(
    { length: 101 },
    (_, i) =>
      `commit refs/heads/main\ncommitter Fixture <fixture@example.invalid> ${1700000000 + i} +0000\ndata 7\nfixture\n\n`,
  ).join("");
  execFileSync("git", ["-C", repo, "fast-import", "--quiet"], { input });
  execFileSync("git", ["-C", repo, "symbolic-ref", "HEAD", "refs/heads/main"]);
  const result = guest.inventory(repo, join(dir, "snapshot"), snapshot.url);
  expect(result.snapshot.history).toEqual({ commits: 100, truncated: true });
  expect(result.fetchedCommits).toHaveLength(100);
});
