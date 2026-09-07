import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readlink, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, it } from "vitest";

const helperPath = "../support/opengrep-image.mjs";
const { prepareOpengrepWork, verifyOpengrepImage } = await import(helperPath);
const owned: string[] = [];
afterEach(async () => {
  for (const root of owned.splice(0)) await rm(root, { recursive: true, force: true });
});
async function layout() {
  const root = await mkdtemp(join(tmpdir(), "vs-opengrep-image-"));
  owned.push(root);
  const files = [
    {
      path: "/opt/vibeshield/rules/manifest.json",
      bytes: JSON.stringify({ rules: [{ path: "opengrep/rule.yml" }], artifacts: [] }),
    },
    { path: "/opt/vibeshield/rules/opengrep/rule.yml", bytes: "rules: []\n" },
    { path: "/usr/local/bin/export-results.mjs", bytes: "// installed export\n" },
  ];
  for (const file of files) {
    await mkdir(dirname(join(root, file.path)), { recursive: true });
    await writeFile(join(root, file.path), file.bytes);
  }
  await symlink(
    "/usr/local/bin/export-results.mjs",
    join(root, "/usr/local/bin/vibeshield-export-results"),
  );
  await mkdir(join(root, "/opt/vibeshield/opengrep-home/.cache/opengrep/v1.25.0/semgrep/bin"), {
    recursive: true,
  });
  for (const file of ["opengrep.bin", "semgrep/bin/opengrep-core"])
    await writeFile(
      join(root, `/opt/vibeshield/opengrep-home/.cache/opengrep/v1.25.0/${file}`),
      "prewarmed fixture",
      { mode: 0o755 },
    );
  return {
    root,
    expected: files.map(({ path, bytes }) => ({
      path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    })),
  };
}
it("prepares disposable work twice without recreating installed image directories or symlinks", async () => {
  const { root, expected } = await layout();
  const home = join(root, "/opt/vibeshield/opengrep-home");
  const before = await stat(home);
  expect(() => verifyOpengrepImage(expected, root)).not.toThrow();
  expect(() => prepareOpengrepWork(root)).not.toThrow();
  expect(() => prepareOpengrepWork(root)).not.toThrow();
  expect((await stat(home)).mtimeMs).toBe(before.mtimeMs);
  expect(await readlink(join(root, "/usr/local/bin/vibeshield-export-results"))).toBe(
    "/usr/local/bin/export-results.mjs",
  );
  expect(await readFile(join(root, "/work/upstream-tests/rule.yml"), "utf8")).toBe("rules: []\n");
});
it("rejects missing or altered image artifacts and absent prewarmed cache without repairing them", async () => {
  const { root, expected } = await layout();
  const rule = join(root, "/opt/vibeshield/rules/opengrep/rule.yml");
  await writeFile(rule, "altered");
  expect(() => verifyOpengrepImage(expected, root)).toThrow(/image artifact/i);
  expect(await readFile(rule, "utf8")).toBe("altered");
  await rm(rule);
  expect(() => verifyOpengrepImage(expected, root)).toThrow(/image artifact/i);
  await writeFile(rule, "rules: []\n");
  await rm(
    join(root, "/opt/vibeshield/opengrep-home/.cache/opengrep/v1.25.0/semgrep/bin/opengrep-core"),
  );
  expect(() => verifyOpengrepImage(expected, root)).toThrow(/prewarmed cache/i);
});
