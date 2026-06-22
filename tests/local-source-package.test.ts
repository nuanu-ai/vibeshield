import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createLocalSourcePackage } from "../src/stages/local-source-package.js";

const execFileP = promisify(execFile);

describe("local source packaging", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "vibeshield-local-source-"));
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("requires a Git worktree root for local scans", async () => {
    const source = path.join(dir, "not-git");
    await mkdir(source);
    await writeFile(path.join(source, "README.md"), "# Not Git\n");

    await expect(createLocalSourcePackage(source)).rejects.toThrow(
      "Local source must be a Git worktree root",
    );
  });

  it("uses Git-filtered files and still includes env files for secret scanning", async () => {
    const source = path.join(dir, "repo");
    await mkdir(source);
    await writeFile(path.join(source, ".gitignore"), ".env\nignored.txt\n");
    await writeFile(path.join(source, "app.ts"), "export const ok = true;\n");
    await writeFile(path.join(source, ".env"), "TOKEN=TEST_STRIPE_SECRET_PLACEHOLDER\n");
    await writeFile(path.join(source, "ignored.txt"), "ignore me\n");
    await initGitRepo(source);

    const pkg = await createLocalSourcePackage(source);
    const extract = path.join(dir, "extract");
    await mkdir(extract);
    try {
      await execFileP("tar", ["-xf", pkg.archivePath, "-C", extract]);

      await expect(readFile(path.join(extract, "app.ts"), "utf8")).resolves.toContain("ok");
      await expect(readFile(path.join(extract, ".env"), "utf8")).resolves.toContain("TOKEN=");
      await expect(readFile(path.join(extract, "ignored.txt"), "utf8")).rejects.toThrow();
      expect(pkg.commitSha).toMatch(/^[0-9a-f]{40}$/);
      expect(pkg.exclusions).toContainEqual({ path: "ignored.txt", reason: "git-ignored" });
    } finally {
      await pkg.cleanup();
    }
  });

  it("records deleted tracked files as missing instead of failing the scan", async () => {
    const source = path.join(dir, "repo");
    await mkdir(source);
    await writeFile(path.join(source, "app.ts"), "export const ok = true;\n");
    await writeFile(path.join(source, "deleted.ts"), "export const gone = true;\n");
    await initGitRepo(source, ["app.ts", "deleted.ts"]);
    await unlink(path.join(source, "deleted.ts"));

    const pkg = await createLocalSourcePackage(source);
    const extract = path.join(dir, "extract");
    await mkdir(extract);
    try {
      await execFileP("tar", ["-xf", pkg.archivePath, "-C", extract]);

      await expect(readFile(path.join(extract, "app.ts"), "utf8")).resolves.toContain("ok");
      await expect(readFile(path.join(extract, "deleted.ts"), "utf8")).rejects.toThrow();
      expect(pkg.exclusions).toContainEqual({ path: "deleted.ts", reason: "missing" });
    } finally {
      await pkg.cleanup();
    }
  });
});

async function initGitRepo(source: string, files = [".gitignore", "app.ts"]): Promise<void> {
  await execFileP("git", ["init"], { cwd: source });
  await execFileP("git", ["config", "user.email", "vibeshield-test@example.com"], {
    cwd: source,
  });
  await execFileP("git", ["config", "user.name", "VibeShield Test"], { cwd: source });
  await execFileP("git", ["add", ...files], { cwd: source });
  await execFileP("git", ["commit", "-m", "fixture"], { cwd: source });
}
