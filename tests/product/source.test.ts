import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink, truncate, writeFile } from "node:fs/promises";
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
  "https://github.com:443/a/b",
  "https://github.com:/a/b",
  "https://@github.com/a/b",
  "https://:@github.com/a/b",
  "https://user:@github.com/a/b",
  "https://:password@github.com/a/b",
  "https://github.com./a/b",
  "https://github。com/a/b",
  "https://ｇｉｔｈｕｂ.com/a/b",
  "https://gіthub.com/a/b",
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
  expect(parseRepositoryUrl("https://GitHub.COM/Owner/Repo")).toBe("https://github.com/Owner/Repo");
  expect(guest.parseRepositoryUrl("https://GitHub.COM/Owner/Repo")).toBe(
    "https://github.com/Owner/Repo",
  );
});
it("classifies bounded guest Git failures without returning diagnostic text", () => {
  expect(typeof guest.classifyGitFailure).toBe("function");
  const results = [
    guest.classifyGitFailure({ error: { code: "ETIMEDOUT", message: "fixture-private-text" } }),
    guest.classifyGitFailure({ signal: "SIGXFSZ", stderr: "fixture-private-text" }),
    guest.classifyGitFailure({ error: { code: "EFBIG", message: "fixture-private-text" } }),
    guest.classifyGitFailure({
      error: { code: "ENOBUFS", message: "fixture-private-text" },
      signal: "SIGTERM",
    }),
    guest.classifyGitFailure({
      status: 128,
      signal: null,
      stderr: Buffer.from("fatal: fetch-pack: invalid index-pack output\nfixture-private-text"),
    }),
    guest.classifyGitFailure(
      {
        status: 128,
        signal: null,
        stderr: Buffer.from("fatal: fetch-pack: invalid index-pack output\nfixture-private-text"),
      },
      true,
    ),
    guest.classifyGitFailure({ status: 128, stderr: "fixture-private-text" }),
  ];
  expect(results).toEqual([
    "timeout",
    "file_limit",
    "file_limit",
    "snapshot_limit",
    "git_failed",
    "file_limit",
    "git_failed",
  ]);
  expect(JSON.stringify(results)).not.toContain("fixture-private-text");
});
it("fetches a default branch without checkout and preserves exact file-limit evidence", async () => {
  expect(typeof guest.fetchRepository).toBe("function");
  expect(typeof guest.cloneFileLimitReached).toBe("function");
  const dir = await realpath(await mkdtemp(join(tmpdir(), "vs-fetch-fixture-")));
  dirs.push(dir);
  const fetched = join(dir, "fetched");
  const calls: string[][] = [];
  const success = (_file: string, args: string[]) => {
    calls.push(args);
    return { status: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
  };
  guest.fetchRepository(snapshot.url, fetched, success);
  expect(calls).toEqual([
    ["init", "--quiet", "--template=", fetched],
    [
      "-C",
      fetched,
      "fetch",
      "--depth=100",
      "--no-tags",
      "--no-recurse-submodules",
      "--",
      snapshot.url,
      "HEAD",
    ],
    ["-C", fetched, "update-ref", "HEAD", "FETCH_HEAD"],
  ]);
  expect(calls.flat()).not.toContain("checkout");
  const packDirectory = join(fetched, ".git", "objects", "pack");
  await mkdir(packDirectory, { recursive: true });
  const pack = join(packDirectory, "tmp_pack_fixture");
  await writeFile(pack, "");
  await truncate(pack, 64 * 1024 * 1024);
  expect(guest.cloneFileLimitReached(fetched)).toBe(true);
  await truncate(pack, 64 * 1024 * 1024 - 1);
  expect(guest.cloneFileLimitReached(fetched)).toBe(false);
  await truncate(pack, 64 * 1024 * 1024);
  const error = (() => {
    try {
      guest.fetchRepository(snapshot.url, fetched, (_file: string, args: string[]) =>
        args.includes("fetch")
          ? {
              status: 128,
              signal: null,
              stdout: Buffer.alloc(0),
              stderr: Buffer.from("fatal: fetch-pack: invalid index-pack output\n"),
            }
          : { status: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) },
      );
    } catch (caught) {
      return caught;
    }
  })();
  expect(error).toMatchObject({ code: "file_limit", message: "Repository acquisition failed" });
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
it("classifies malformed acquisition exports without retaining their contents", async () => {
  const runtime = new FakeSandboxRuntime({
    exec: async (argv, session) => {
      if (argv.includes("/usr/local/bin/vibeshield-acquire"))
        await session.uploadBytes(
          "/work/.vibeshield/exports/snapshot.json",
          Buffer.from(`{"snapshot":{"commit":"fixture-private-text"}}`),
        );
      return { exitCode: 0, stdout: "", stderr: "" };
    },
  });
  const session = await runtime.create({ name: "invalid-source", imageTag: "fixture" });
  const error = await acquire(session, snapshot.url, new AbortController().signal).catch(
    (caught: unknown) => caught,
  );
  expect(error).toMatchObject({
    name: "AcquisitionError",
    message: "Repository acquisition failed",
    code: "invalid_snapshot",
  });
  expect(JSON.stringify(error)).not.toContain("fixture-private-text");
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
  {
    exitCode: 1,
    stderr: "VIBESHIELD_ACQUIRE_FAILURE=file_limit\nfixture-private-text",
    expected: "file_limit",
  },
  {
    exitCode: 1,
    stderr: "VIBESHIELD_ACQUIRE_FAILURE=snapshot_limit\n",
    expected: "snapshot_limit",
  },
  { exitCode: 124, stderr: "fixture-private-text", expected: "timeout" },
  {
    exitCode: 1,
    stderr: "VIBESHIELD_ACQUIRE_FAILURE=fixture-private-text\n",
    expected: "git_failed",
  },
])("classifies acquisition failure as $expected without retaining stderr", async (failure) => {
  const runtime = new FakeSandboxRuntime({
    exec: () => ({
      exitCode: failure.exitCode,
      stdout: "fixture-private-text",
      stderr: failure.stderr,
    }),
  });
  const session = await runtime.create({ name: `source-${failure.expected}`, imageTag: "fixture" });
  const error = await acquire(session, snapshot.url, new AbortController().signal).catch(
    (caught: unknown) => caught,
  );
  expect(error).toMatchObject({
    name: "AcquisitionError",
    message: "Repository acquisition failed",
    code: failure.expected,
  });
  expect(JSON.stringify(error)).not.toContain("fixture-private-text");
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
