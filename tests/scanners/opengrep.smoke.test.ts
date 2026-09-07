/** Actual pinned-engine acceptance. Run with VIBESHIELD_LIVE_OPENGREP=1. */
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { Sandbox } from "microsandbox";
import { expect, it } from "vitest";
import { MicrosandboxRuntime } from "../../src/adapters/microsandbox/runtime.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { scanOpengrep } from "../../src/scan/scanners/opengrep.js";
import { makeReportInput } from "../support/findings.js";

const live = it.runIf(process.env.VIBESHIELD_LIVE_OPENGREP === "1");
live(
  "pinned engine validates upstream rules and resists repository ignores and inline suppressions across vulnerable, fixed and clean inputs",
  async () => {
    const runtime = new MicrosandboxRuntime();
    const name = `vs-opengrep-acceptance-${Date.now()}`;
    try {
      const session = await runtime.create({ name, imageTag: "vibeshield-toolchain:latest" });
      expect((await session.exec(["opengrep", "--version"])).stdout.trim()).toBe("1.25.0");
      const architecture = (await session.exec(["uname", "-m"])).stdout.trim();
      const releaseHashes: Record<string, string> = {
        aarch64: "fd40124272d006082a5594b19aecee07b01dd50933d8add7a4fd5c557d2be5f6",
        x86_64: "9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33",
      };
      const binaryHash = (
        await session.exec(["sha256sum", "/usr/local/bin/opengrep"])
      ).stdout.split(/\s+/)[0];
      expect(binaryHash).toBe(releaseHashes[architecture]);
      const manifestBytes = await readFile(
        new URL("../../toolchain/rules/manifest.json", import.meta.url),
      );
      const manifest = JSON.parse(manifestBytes.toString());
      expect(
        (
          await session.exec([
            "mkdir",
            "-p",
            "/opt/vibeshield/rules",
            ...[...manifest.rules, ...manifest.artifacts].map((artifact) =>
              dirname(`/opt/vibeshield/rules/${artifact.path}`),
            ),
          ])
        ).exitCode,
      ).toBe(0);
      await session.uploadBytes("/opt/vibeshield/rules/manifest.json", manifestBytes);
      for (const artifact of [...manifest.rules, ...manifest.artifacts]) {
        await session.uploadBytes(
          `/opt/vibeshield/rules/${artifact.path}`,
          await readFile(new URL(`../../toolchain/rules/${artifact.path}`, import.meta.url)),
        );
      }
      for (const [local, remote] of [
        ["opengrep.mjs", "vibeshield-opengrep"],
        ["export-results.mjs", "export-results.mjs"],
      ]) {
        await session.uploadBytes(
          `/usr/local/bin/${remote}`,
          await readFile(new URL(`../../toolchain/${local}`, import.meta.url)),
        );
      }
      await session.uploadBytes("/opt/vibeshield/opengrep.ignore", Buffer.from(""));
      await session.uploadBytes("/opt/vibeshield/opengrep-settings.yml", Buffer.from("{}\n"));
      await session.uploadBytes(
        "/work/setup.mjs",
        Buffer.from(`
      import {mkdirSync,copyFileSync,readFileSync,symlinkSync} from 'node:fs';
      import {dirname} from 'node:path';
      for (const p of ['/work/.vibeshield','/work/.vibeshield/exports','/work/.vibeshield/tmp','/work/snapshot','/work/upstream-tests','/opt/vibeshield/opengrep-home','/opt/vibeshield/opengrep-home/.cache']) mkdirSync(p,{mode:0o700});
      // The existing image has already extracted this exact engine. Reuse its
      // image-owned cache in this disposable VM, equivalent to Docker prewarming.
      symlinkSync('/root/.cache/opengrep','/opt/vibeshield/opengrep-home/.cache/opengrep');
      symlinkSync('/usr/local/bin/export-results.mjs','/usr/local/bin/vibeshield-export-results');
      const manifest=JSON.parse(readFileSync('/opt/vibeshield/rules/manifest.json'));
      for (const a of [...manifest.rules,...manifest.artifacts].filter(x=>/\\.(yml|js|ts)$/.test(x.path))) {
        const dest='/work/upstream-tests/'+a.path.replace(/^(opengrep|fixtures)\\//,'');
        mkdirSync(dirname(dest),{recursive:true});copyFileSync('/opt/vibeshield/rules/'+a.path,dest);
      }
    `),
      );
      expect((await session.exec(["node", "/work/setup.mjs"])).exitCode).toBe(0);
      const upstream = await session.exec(
        ["opengrep", "scan", "--test", "--no-rewrite-rule-ids", "/work/upstream-tests"],
        { timeoutMs: 115_000 },
      );
      expect(upstream.exitCode, "upstream annotations must pass").toBe(0);
      expect(upstream.stdout).toContain("All tests passed");
      for (const file of ["vulnerable.ts", "fixed.ts", "clean.ts"]) {
        await session.uploadBytes(
          `/work/snapshot/${file}`,
          await readFile(new URL(`../fixtures/scanners/code/${file}`, import.meta.url)),
        );
      }
      await session.uploadBytes("/work/snapshot/.semgrepignore", Buffer.from("*.ts\n"));
      await session.uploadBytes("/work/snapshot/.gitignore", Buffer.from("*.ts\n"));
      // A tracked repository config is ordinary input, never the selected service rules.
      await session.uploadBytes("/work/snapshot/.semgrep.yml", Buffer.from("rules: []\n"));
      const snapshot: Snapshot = {
        url: "https://github.com/fixture/code",
        commit: "a".repeat(40),
        files: [
          "vulnerable.ts",
          "fixed.ts",
          "clean.ts",
          ".semgrepignore",
          ".gitignore",
          ".semgrep.yml",
        ],
        languages: ["TypeScript"],
        history: { commits: 1, truncated: false },
      };
      const parsed = await scanOpengrep({
        session,
        snapshot,
        signal: new AbortController().signal,
      });
      expect(parsed.coverage[0]?.status).toBe("checked");
      expect([...new Set(parsed.findings.map((x) => x.ruleId))].sort()).toEqual(
        manifest.rules.map((x: { id: string }) => x.id).sort(),
      );
      expect(
        parsed.findings.every((x) => x.locations.every((y) => y.path === "vulnerable.ts")),
      ).toBe(true);
      const taint = parsed.findings.find(
        (x) => x.ruleId === "rules_lgpl_javascript_ssrf_rule-node-ssrf",
      );
      expect(taint).toMatchObject({ confidence: "high", code: { mode: "taint" } });
      expect(taint?.evidence).toMatch(/flow:.*vulnerable.ts/);
      const report = buildReport({ ...makeReportInput([parsed]), policy: defaultPolicy });
      expect(report.issues).toHaveLength(2);
      expect(
        report.issues.some((issue) =>
          issue.findingIds.some((id) => id.includes("rules_lgpl_javascript_ssrf_rule-node-ssrf")),
        ),
      ).toBe(true);
    } finally {
      await runtime.destroy(name);
      expect((await Sandbox.list()).filter((x) => x.name === name)).toHaveLength(0);
    }
  },
  120_000,
);
