/** Image-native acceptance by default; old-image development layouts are explicit. */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { Sandbox } from "microsandbox";
import { expect, it } from "vitest";
import { MicrosandboxRuntime } from "../../src/adapters/microsandbox/runtime.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { parseOpengrepSarif, scanOpengrep } from "../../src/scan/scanners/opengrep.js";
import { readScannerJson } from "../../src/scan/scanners/shared.js";
import { makeReportInput } from "../support/findings.js";

const live = it.runIf(process.env.VIBESHIELD_LIVE_OPENGREP === "1");
const layout = process.env.VIBESHIELD_OPENGREP_TEST_LAYOUT ?? "installed";
live(
  `pinned engine (${layout}) validates upstream rules, applicability and ignore resistance across vulnerable, fixed and clean inputs`,
  async () => {
    const runtime = new MicrosandboxRuntime();
    const name = `vs-opengrep-acceptance-${Date.now()}`;
    try {
      const session = await runtime.create({ name, imageTag: "vibeshield-toolchain:latest" });
      expect(["installed", "inject", "rebuilt"]).toContain(layout);
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
      const installedFiles = [
        { path: "/opt/vibeshield/rules/manifest.json", bytes: manifestBytes },
      ];
      for (const artifact of [...manifest.rules, ...manifest.artifacts]) {
        installedFiles.push({
          path: `/opt/vibeshield/rules/${artifact.path}`,
          bytes: await readFile(new URL(`../../toolchain/rules/${artifact.path}`, import.meta.url)),
        });
      }
      for (const [local, remote] of [
        ["opengrep.mjs", "vibeshield-opengrep"],
        ["export-results.mjs", "export-results.mjs"],
      ]) {
        installedFiles.push({
          path: `/usr/local/bin/${remote}`,
          bytes: await readFile(new URL(`../../toolchain/${local}`, import.meta.url)),
        });
      }
      installedFiles.push(
        { path: "/opt/vibeshield/opengrep.ignore", bytes: Buffer.from("") },
        { path: "/opt/vibeshield/opengrep-settings.yml", bytes: Buffer.from("{}\n") },
      );
      // Explicit disposable-VM development setup only. Never overwrite an existing
      // installed artifact, even in these modes; later validation rejects stale bytes.
      if (layout !== "installed") {
        for (const file of installedFiles) {
          const exists = await session.exec(["test", "-e", file.path]);
          const link = await session.exec(["test", "-L", file.path]);
          if (exists.exitCode === 1 && link.exitCode === 1) {
            expect((await session.exec(["mkdir", "-p", dirname(file.path)])).exitCode).toBe(0);
            await session.uploadBytes(file.path, file.bytes);
          } else expect([exists.exitCode, link.exitCode]).toContain(0);
        }
        await session.uploadBytes(
          "/work/bootstrap-opengrep.mjs",
          Buffer.from(`
          import {existsSync,mkdirSync,symlinkSync} from 'node:fs';
          import {execFileSync} from 'node:child_process';
          const cache='/opt/vibeshield/opengrep-home/.cache/opengrep';
          if (!existsSync(cache)) {
            mkdirSync('/opt/vibeshield/opengrep-home/.cache',{recursive:true,mode:0o700});
            // Real directories model the rebuilt image; file leaves point to
            // the exact prewarmed engine so overlay copy-up cannot hit RLIMIT_FSIZE.
            ${layout === "rebuilt" ? "execFileSync('cp',['-as','/root/.cache/opengrep',cache]);" : "symlinkSync('/root/.cache/opengrep',cache);"}
          }
          const link='/usr/local/bin/vibeshield-export-results';
          if (!existsSync(link)) symlinkSync('/usr/local/bin/export-results.mjs',link);
        `),
        );
        const bootstrap = await session.exec(["node", "/work/bootstrap-opengrep.mjs"]);
        expect(bootstrap.exitCode, bootstrap.stderr).toBe(0);
      }
      await session.uploadBytes(
        "/work/opengrep-image.mjs",
        await readFile(new URL("../support/opengrep-image.mjs", import.meta.url)),
      );
      await session.uploadBytes(
        "/work/opengrep-image-files.json",
        Buffer.from(
          JSON.stringify(
            installedFiles.map(({ path, bytes }) => ({
              path,
              sha256: createHash("sha256").update(bytes).digest("hex"),
            })),
          ),
        ),
      );
      await session.uploadBytes(
        "/work/setup.mjs",
        Buffer.from(`
      import {readFileSync} from 'node:fs';
      import {prepareOpengrepWork,verifyOpengrepImage} from './opengrep-image.mjs';
      verifyOpengrepImage(JSON.parse(readFileSync('/work/opengrep-image-files.json','utf8')),'/',${layout === "inject"});
      prepareOpengrepWork();
    `),
      );
      const setup = await session.exec(["node", "/work/setup.mjs"]);
      expect(setup.exitCode, setup.stderr).toBe(0);
      // Repeated acceptance setup must not recreate image-owned directories/links.
      expect((await session.exec(["node", "/work/setup.mjs"])).exitCode).toBe(0);
      const serviceEnv = { HOME: "/opt/vibeshield/opengrep-home" };
      expect(
        (await session.exec(["opengrep", "--version"], { env: serviceEnv })).stdout.trim(),
      ).toBe("1.25.0");
      const upstream = await session.exec(
        ["opengrep", "scan", "--test", "--no-rewrite-rule-ids", "/work/upstream-tests"],
        { timeoutMs: 115_000, env: serviceEnv },
      );
      expect(upstream.exitCode, "upstream annotations must pass").toBe(0);
      expect(upstream.stdout).toContain("All tests passed");
      await session.uploadBytes(
        "/work/snapshot/app.py",
        Buffer.from("print('static-only fixture')\n"),
      );
      const unsupported: Snapshot = {
        url: "https://github.com/fixture/code",
        commit: "a".repeat(40),
        files: ["app.py"],
        languages: ["Python"],
        history: { commits: 1, truncated: false },
  oversized: 0,
      };
      // Characterize the actual engine's silent empty result for Python-only
      // input, then prove this is not misreported as successful JS/TS coverage.
      expect((await session.exec(["node", "/usr/local/bin/vibeshield-opengrep"])).exitCode).toBe(0);
      const unsupportedRaw = await readScannerJson(
        session,
        "/work/.vibeshield/exports/opengrep.json",
      );
      expect(unsupportedRaw).toMatchObject({
        runs: [
          {
            results: [],
            invocations: [
              {
                executionSuccessful: true,
                toolExecutionNotifications: [],
              },
            ],
          },
        ],
      });
      const configWarnings = unsupportedRaw as {
        runs: [{ invocations: [{ toolConfigurationNotifications?: unknown[] }] }];
      };
      expect(configWarnings.runs[0].invocations[0].toolConfigurationNotifications ?? []).toEqual(
        [],
      );
      expect(parseOpengrepSarif(unsupportedRaw, unsupported)).toMatchObject({
        findings: [],
        coverage: [{ status: "skipped", applicable: false }],
      });
      expect(
        await scanOpengrep({
          session,
          snapshot: unsupported,
          signal: new AbortController().signal,
        }),
      ).toMatchObject({ findings: [], coverage: [{ status: "skipped", applicable: false }] });
      // Exports are intentionally create-once. Keep the first fixture's export
      // separate before exercising the next independent scan in this owned VM.
      expect(
        (
          await session.exec([
            "mv",
            "/work/.vibeshield/exports/opengrep.json",
            "/work/.vibeshield/python-opengrep.json",
          ])
        ).exitCode,
      ).toBe(0);
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
          "app.py",
          "vulnerable.ts",
          "fixed.ts",
          "clean.ts",
          ".semgrepignore",
          ".gitignore",
          ".semgrep.yml",
        ],
        languages: ["Python", "TypeScript"],
        history: { commits: 1, truncated: false },
  oversized: 0,
      };
      const parsed = await scanOpengrep({
        session,
        snapshot,
        signal: new AbortController().signal,
      });
      expect(parsed.coverage[0]).toMatchObject({ status: "checked", applicable: true });
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
