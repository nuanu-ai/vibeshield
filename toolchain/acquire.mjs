#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  gitEnvironment,
  ignored,
  MAX_EXPORT_BYTES,
  SERVICE,
  safePath,
  writeExport,
} from "./export-results.mjs";

export function parseRepositoryUrl(value) {
  try {
    if (/[\\\s%]/.test(value)) throw new Error();
    const authority = /^https:\/\/([^/]+)\//.exec(value)?.[1];
    if (!authority || !/^github\.com$/i.test(authority)) throw new Error();
    const parsed = new URL(value);
    const rawPath = value.replace(/^https:\/\/[^/]+/, "");
    if (
      parsed.protocol !== "https:" ||
      parsed.hostname !== "github.com" ||
      parsed.port ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(rawPath) ||
      rawPath !== parsed.pathname
    )
      throw new Error();
    const [owner, name] = parsed.pathname.slice(1).replace(/\/$/, "").split("/");
    const repo = name?.replace(/\.git$/, "");
    if (!owner || !repo || [owner, repo].some((part) => part === "." || part === ".."))
      throw new Error();
    return `https://github.com/${owner}/${repo}`;
  } catch {
    throw new Error("Enter a public GitHub repository URL");
  }
}
function git(repo, args, maxBuffer = MAX_EXPORT_BYTES) {
  const result = spawnSync("git", ["-C", repo, ...args], {
    env: gitEnvironment(),
    maxBuffer,
    timeout: 110_000,
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error || result.signal || result.status !== 0)
    throw new Error("Repository acquisition failed");
  return result.stdout;
}
export function inventory(repo, destination, url) {
  const commit = git(repo, ["rev-parse", "HEAD"]).toString("utf8").trim();
  const fetchedHistory = git(repo, ["rev-list", "--max-count=101", "HEAD"])
    .toString("utf8")
    .trim()
    .split("\n");
  const fetchedCommits = fetchedHistory.slice(0, 100);
  const shallow = git(repo, ["rev-parse", "--is-shallow-repository"]).toString("utf8").trim();
  if (
    !/^[a-f0-9]{40}$/.test(commit) ||
    fetchedCommits.some((id) => !/^[a-f0-9]{40}$/.test(id)) ||
    !["true", "false"].includes(shallow)
  )
    throw new Error("Invalid snapshot");
  const tree = new TextDecoder("utf-8", { fatal: true }).decode(
    git(repo, ["ls-tree", "-rz", "--long", "--full-tree", "HEAD"]),
  );
  const entries = [];
  let total = 0;
  for (const record of tree.split("\0").filter(Boolean)) {
    const match = /^(\d{6}) (blob|commit) ([a-f0-9]{40}) +(-|\d+)\t([\s\S]+)$/.exec(record);
    if (!match) throw new Error("Invalid snapshot");
    const [, mode, , oid, sizeText, path] = match;
    if (!["100644", "100755"].includes(mode)) continue;
    if (path.split("/").some((part) => ignored.has(part))) continue;
    if (!safePath(path)) throw new Error("Invalid snapshot");
    const size = Number(sizeText);
    total += size;
    if (
      !Number.isSafeInteger(size) ||
      size < 0 ||
      size > 5 * 1024 * 1024 ||
      total > 500 * 1024 * 1024 ||
      entries.length >= 50_000
    )
      throw new Error("Snapshot limit exceeded");
    entries.push({ path, size, kind: "file", oid });
  }
  mkdirSync(destination, { mode: 0o700 });
  for (const entry of entries) {
    const path = join(destination, entry.path);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const contents = git(repo, ["cat-file", "blob", entry.oid], 5 * 1024 * 1024 + 1);
    if (contents.length !== entry.size) throw new Error("Invalid snapshot");
    writeFileSync(path, contents, { flag: "wx", mode: 0o600 });
  }
  const languageByExtension = {
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".py": "Python",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".cs": "C#",
    ".c": "C",
    ".cpp": "C++",
  };
  return {
    snapshot: {
      url,
      commit,
      files: entries.map((entry) => entry.path),
      languages: [
        ...new Set(
          entries.map((entry) => languageByExtension[extname(entry.path)]).filter(Boolean),
        ),
      ].sort(),
      history: {
        commits: fetchedCommits.length,
        truncated: shallow === "true" || fetchedHistory.length > 100,
      },
    },
    entries: entries.map(({ path, size, kind }) => ({ path, size, kind })),
    fetchedCommits,
  };
}
function main() {
  const url = parseRepositoryUrl(process.argv[2]);
  // /work is already a hard bounded tmpfs and run-check starts its guard before
  // this process. Exclusive service directories prevent accepting stale exports.
  mkdirSync(SERVICE, { mode: 0o700 });
  mkdirSync(`${SERVICE}/exports`, { mode: 0o700 });
  mkdirSync(`${SERVICE}/tmp`, { mode: 0o700 });
  const clone = spawnSync(
    "git",
    [
      "clone",
      "--depth=100",
      "--single-branch",
      "--no-tags",
      "--no-recurse-submodules",
      "--no-checkout",
      "--template=",
      "--",
      url,
      "/work/repository",
    ],
    { cwd: "/work", env: gitEnvironment(), stdio: "ignore", timeout: 110_000 },
  );
  if (clone.error || clone.signal || clone.status !== 0)
    throw new Error("Repository acquisition failed");
  writeExport(
    `${SERVICE}/exports/snapshot.json`,
    inventory("/work/repository", "/work/snapshot", url),
  );
}
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch {
    process.stderr.write("Repository acquisition failed\n");
    process.exitCode = 1;
  }
}
