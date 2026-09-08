/** Pinned-engine acceptance in a disposable VM; no host target execution. */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Sandbox } from "microsandbox";
import { expect, it } from "vitest";
import { MicrosandboxRuntime } from "../../src/adapters/microsandbox/runtime.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { readScannerJson } from "../../src/scan/scanners/shared.js";
import { scanZizmor } from "../../src/scan/scanners/zizmor.js";
import { makeReportInput } from "../support/findings.js";

const live = it.runIf(process.env.VIBESHIELD_LIVE_ZIZMOR === "1");
const layout = process.env.VIBESHIELD_ZIZMOR_TEST_LAYOUT ?? "installed";
live(
  `pinned zizmor (${layout}) reports injection through suppression attempts, accepts fixed input and fails invalid YAML`,
  async () => {
    const runtime = new MicrosandboxRuntime();
    const name = `vs-zizmor-acceptance-${Date.now()}`;
    try {
      const session = await runtime.create({ name, imageTag: "vibeshield-toolchain:latest" });
      expect(["installed", "inject"]).toContain(layout);
      if (layout === "inject") {
        const archive = process.env.VIBESHIELD_ZIZMOR_TEST_ARCHIVE;
        if (!archive)
          throw new Error(
            "Set VIBESHIELD_ZIZMOR_TEST_ARCHIVE to the digest-verified official Linux archive",
          );
        const bytes = await readFile(archive);
        const arch = (await session.exec(["uname", "-m"])).stdout.trim();
        const digest =
          arch === "aarch64"
            ? "018a024d6b6d09733b07f6ef42838d984c23ec04bc9b2acd55f7d67826aeafe5"
            : "ec8c95cd800845abb9bbc5f377ec7c57d2eb8e2386a00a201d3a74ee4092e5ed";
        expect(createHash("sha256").update(bytes).digest("hex")).toBe(digest);
        await session.uploadBytes("/work/zizmor.tar.gz", bytes);
        expect(
          (await session.exec(["tar", "-xzf", "/work/zizmor.tar.gz", "-C", "/usr/local/bin"]))
            .exitCode,
        ).toBe(0);
      }
      expect((await session.exec(["zizmor", "--version"])).stdout.trim()).toBe("zizmor 1.30.0");
      for (const [local, remote] of [
        ["zizmor.mjs", "/usr/local/bin/vibeshield-zizmor"],
        ["export-results.mjs", "/usr/local/bin/export-results.mjs"],
      ] as const) {
        const bytes = await readFile(new URL(`../../toolchain/${local}`, import.meta.url));
        if (layout === "inject" && (await session.exec(["test", "-e", remote])).exitCode === 1)
          await session.uploadBytes(remote, bytes);
        expect(
          createHash("sha256")
            .update(await session.read(remote))
            .digest("hex"),
        ).toBe(createHash("sha256").update(bytes).digest("hex"));
      }
      expect(
        (
          await session.exec([
            "mkdir",
            "-p",
            "/work/snapshot/.github/workflows",
            "/work/.vibeshield/exports",
            "/work/.vibeshield/tmp",
            "/opt/vibeshield",
          ])
        ).exitCode,
      ).toBe(0);
      if (layout === "inject") {
        expect(
          (await session.exec(["node", "/usr/local/bin/vibeshield-zizmor", "install-config"]))
            .exitCode,
        ).toBe(0);
        if (
          (await session.exec(["test", "-e", "/usr/local/bin/vibeshield-export-results"]))
            .exitCode === 1
        )
          expect(
            (
              await session.exec([
                "ln",
                "-s",
                "/usr/local/bin/export-results.mjs",
                "/usr/local/bin/vibeshield-export-results",
              ])
            ).exitCode,
          ).toBe(0);
      }
      const snapshot: Snapshot = {
        url: "https://github.com/fixture/workflows",
        commit: "a".repeat(40),
        files: [".github/workflows/vulnerable.yml", ".github/workflows/fixed.yml"],
        languages: [],
        history: { commits: 1, truncated: false },
  oversized: 0,
      };
      for (const file of ["vulnerable.yml", "fixed.yml"])
        await session.uploadBytes(
          `/work/snapshot/.github/workflows/${file}`,
          await readFile(new URL(`../fixtures/scanners/workflows/${file}`, import.meta.url)),
        );
      await session.uploadBytes(
        "/work/.vibeshield/exports/snapshot.json",
        Buffer.from(JSON.stringify({ snapshot })),
      );
      // Real config discovery, ignore annotations, and tracked-but-gitignored workflows.
      await session.uploadBytes(
        "/work/snapshot/zizmor.yml",
        Buffer.from("rules:\n  template-injection:\n    disable: true\n"),
      );
      await session.uploadBytes("/work/snapshot/.gitignore", Buffer.from(".github/workflows/\n"));
      const ctx = { session, snapshot, signal: new AbortController().signal };
      const result = await scanZizmor(ctx);
      console.log("zizmor acceptance", JSON.stringify(result));
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toMatchObject({
        ruleId: "template-injection",
        severity: "high",
        confidence: "high",
        locations: [{ path: ".github/workflows/vulnerable.yml", line: 12 }],
      });
      expect(result.coverage[0]?.status).toBe("checked");
      const report = buildReport({ ...makeReportInput([result]), policy: defaultPolicy });
      expect(report.issues).toHaveLength(1);
      expect(report.issues[0]?.remediation).toContain("environment variable");
      const exported = (await readScannerJson(
        session,
        "/work/.vibeshield/exports/zizmor.json",
      )) as { findings: { ident: string }[] };
      expect(exported.findings.map((f) => f.ident)).toEqual(["template-injection"]);
      // Source remains unchanged; the vulnerable fixture's annotation does not suppress output.
      expect(
        Buffer.from(await session.read("/work/snapshot/.github/workflows/vulnerable.yml")),
      ).toEqual(
        await readFile(new URL("../fixtures/scanners/workflows/vulnerable.yml", import.meta.url)),
      );
      // Compare actual CLI behavior, never session stdout JSON. Each mode writes a fresh owned file.
      async function direct(label: string, omit: string[] = [], extra: string[] = []) {
        const script = `import { spawnSync } from 'node:child_process'; import { openSync,closeSync } from 'node:fs'; import { zizmorCommand } from '/usr/local/bin/vibeshield-zizmor'; import { gitEnvironment } from '/usr/local/bin/export-results.mjs'; const fd=openSync('/work/${label}.json','wx',0o600); const args=zizmorCommand(${JSON.stringify(snapshot.files)}).filter(a=>!${JSON.stringify(omit)}.includes(a)); args.unshift(...${JSON.stringify(extra)}); let result;try{result=spawnSync('/usr/local/bin/zizmor',args,{cwd:'/work/snapshot',env:gitEnvironment(),stdio:['ignore',fd,'ignore']});}finally{closeSync(fd)} process.exitCode=result.status;`;
        await session.uploadBytes(`/work/${label}.mjs`, Buffer.from(script));
        const status = await session.exec(["node", `/work/${label}.mjs`]);
        const bytes = await session.read(`/work/${label}.json`);
        return {
          code: status.exitCode,
          findings: bytes.length
            ? (JSON.parse(Buffer.from(bytes).toString()) as { ident: string }[])
            : [],
        };
      }
      expect((await direct("ignored", ["--no-ignores"])).findings).toEqual([]);
      expect(
        (await direct("repo-config", ["--config=/opt/vibeshield/zizmor.json"])).findings.some(
          (f) => f.ident === "template-injection",
        ),
      ).toBe(false);
      expect((await direct("findings-exit", ["--no-exit-codes"])).code).toBe(14);
      // Replacing vulnerable source with the fixed control must empty the report.
      async function rotate(label: string) {
        for (const file of ["exports/zizmor.json", "zizmor-raw.json", "zizmor-log.txt"])
          if ((await session.exec(["test", "-e", `/work/.vibeshield/${file}`])).exitCode === 0)
            expect(
              (
                await session.exec([
                  "mv",
                  `/work/.vibeshield/${file}`,
                  `/work/.vibeshield/${label}-${file.replaceAll("/", "-")}`,
                ])
              ).exitCode,
            ).toBe(0);
      }
      await rotate("vulnerable");
      await session.uploadBytes(
        "/work/snapshot/.github/workflows/vulnerable.yml",
        await readFile(new URL("../fixtures/scanners/workflows/fixed.yml", import.meta.url)),
      );
      const fixed = await scanZizmor(ctx);
      expect(fixed.findings).toEqual([]);
      expect(fixed.coverage[0]?.status).toBe("checked");
      expect((await direct("clean-exit", ["--no-exit-codes"])).code).toBe(0);
      await rotate("fixed");
      await session.uploadBytes(
        "/work/snapshot/.github/workflows/vulnerable.yml",
        Buffer.from("name: invalid\non: [pull_request\njobs: {}\n"),
      );
      const invalid = await scanZizmor(ctx);
      expect(invalid.findings).toEqual([]);
      expect(invalid.coverage[0]?.status).toBe("failed");
      expect(
        (await session.exec(["test", "-e", "/work/.vibeshield/exports/zizmor.json"])).exitCode,
      ).toBe(1);
      expect((await direct("invalid-exit")).code).toBe(1);
      expect((await session.exec(["zizmor", "--nonexistent-service-flag"])).exitCode).toBe(2);
      expect((await session.exec(["zizmor", "--offline", "zizmorcore/zizmor"])).exitCode).toBe(1);
      await rotate("invalid");
      await session.uploadBytes(
        "/opt/vibeshield/zizmor.json",
        Buffer.from('{"rules":{"template-injection":{"disable":true}}}'),
      );
      expect((await scanZizmor(ctx)).coverage[0]?.status).toBe("failed");
      expect(
        (await session.exec(["test", "-e", "/work/.vibeshield/exports/zizmor.json"])).exitCode,
      ).toBe(1);
    } finally {
      await runtime.destroy(name);
      expect((await Sandbox.list()).some((item) => item.name === name)).toBe(false);
    }
  },
  180_000,
);
