import { createHash } from "node:crypto";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";

const identityPath = "../../toolchain/identity.mjs";
const { contentIdentity } = await import(identityPath);
const verifierPath = "../../toolchain/verify.mjs";
const { verifyInstalled, verifyFiles, verifyRuleManifests } = await import(verifierPath);
const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true });
});
async function fixture() {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "vs-pinned-image-")));
  directories.push(directory);
  await mkdir(join(directory, "rules"));
  await writeFile(join(directory, "versions.json"), '{"version":"1.0.0"}');
  await writeFile(join(directory, "rules", "check.yml"), "original rule\n");
  return directory;
}

// Omitting rules or build scripts from the digest reuses a stale image after edits.
it("changes the accepted image when any build input changes and restores it exactly", async () => {
  const root = await fixture();
  const original = contentIdentity(root);
  expect(original).toMatch(/^vibeshield-toolchain:sha256-[a-f0-9]{64}$/);
  await writeFile(join(root, "rules", "check.yml"), "different rule\n");
  expect(contentIdentity(root)).not.toBe(original);
  await writeFile(join(root, "rules", "check.yml"), "original rule\n");
  expect(contentIdentity(root)).toBe(original);
  await writeFile(join(root, "runner.mjs"), "console.log('new runner');\n");
  expect(contentIdentity(root)).not.toBe(original);
});

// Trusting the tag or merely finding a binary would accept the wrong executable.
it("rejects an installed engine version that differs from its manifest", async () => {
  const root = await fixture();
  const binary = join(root, "scanner");
  await writeFile(binary, '#!/bin/sh\nprintf "scanner 1.0.0\\n"\n', { mode: 0o700 });
  const manifest = {
    engines: {
      sample: {
        version: "2.0.0",
        command: [binary, "--version"],
        versionLine: "scanner 2.0.0",
      },
    },
  };
  expect(() => verifyInstalled(manifest)).toThrow(/version.*sample|sample.*version/i);
  manifest.engines.sample.version = "1.0.0";
  manifest.engines.sample.versionLine = "scanner 1.0.0";
  expect(verifyInstalled(manifest)).toEqual({ sample: "1.0.0" });
});

it("rejects a missing engine instead of accepting manifest-only provenance", () => {
  expect(() =>
    verifyInstalled({
      engines: {
        sample: {
          version: "1.0.0",
          command: ["/nonexistent/vibeshield-engine"],
          versionLine: "1.0.0",
        },
      },
    }),
  ).toThrow(/sample/);
});

it("rejects a different base Node runtime even when engine metadata matches", () => {
  expect(() => verifyInstalled({ engines: {}, base: { version: "0.0.0" } })).toThrow(
    /base.*version/i,
  );
});

// Accepting copied metadata without hashing the installed rule runs another policy.
it("rejects a missing or modified installed rule", async () => {
  const root = await fixture();
  const files = [
    {
      path: "rule.yml",
      sha256: "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
    },
  ];
  expect(() => verifyFiles(files, root)).toThrow();
  await writeFile(join(root, "rule.yml"), "wrong\n");
  expect(() => verifyFiles(files, root)).toThrow();
  await writeFile(join(root, "rule.yml"), "test\n");
  expect(() => verifyFiles(files, root)).not.toThrow();
});

it.each([
  "opengrep",
  "trivy",
])("verifies the actual %s manifest independently of the intact build-input copy", async (engine) => {
  const root = await fixture();
  const source = join(root, "source");
  const installed = join(root, "installed");
  const text = '{"revision":"frozen","reviewedAt":"2026-09-07T00:00:00Z"}\n';
  const manifestPath = engine === "opengrep" ? "rules/manifest.json" : "trivy/manifest.json";
  await mkdir(join(source, engine === "opengrep" ? "rules" : "trivy"), { recursive: true });
  await mkdir(join(installed, engine === "opengrep" ? "rules" : "trivy"), { recursive: true });
  await writeFile(join(source, manifestPath), text);
  const manifest = {
    rules: {
      [engine]: { manifest: manifestPath, sha256: createHash("sha256").update(text).digest("hex") },
    },
  };
  expect(() => verifyRuleManifests(manifest, source, installed)).toThrow();
  await writeFile(join(installed, manifestPath), text.replace("frozen", "modified"));
  expect(() => verifyRuleManifests(manifest, source, installed)).toThrow();
  await writeFile(join(installed, manifestPath), text);
  expect(() => verifyRuleManifests(manifest, source, installed)).not.toThrow();
});

// This list is handed to an image remover, so anything that is not our own
// content-addressed tag must never reach it.
it("selects only our own superseded toolchain tags for removal", async () => {
  const { staleToolchainTags } = await import("../../scripts/prepare-toolchain.js");
  const keep = `vibeshield-toolchain:sha256-${"a".repeat(64)}`;
  const superseded = `vibeshield-toolchain:sha256-${"b".repeat(64)}`;
  expect(
    staleToolchainTags(
      [
        keep,
        superseded,
        superseded,
        "vibeshield-toolchain:latest",
        `vibeshield-toolchain-evil:sha256-${"c".repeat(64)}`,
        `ghcr.io/someone/vibeshield-toolchain:sha256-${"d".repeat(64)}`,
        `vibeshield-toolchain:sha256-${"e".repeat(63)}`,
        "postgres:16",
        "<none>:<none>",
        "",
      ],
      keep,
    ),
  ).toEqual([superseded]);
});
