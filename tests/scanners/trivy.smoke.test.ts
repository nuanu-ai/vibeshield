/** Actual-engine acceptance; injection is explicit disposable development setup. */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { Sandbox } from "microsandbox";
import { expect, it, vi } from "vitest";
import { FakeSandboxRuntime } from "../../src/adapters/fake-sandbox.js";
import { MicrosandboxRuntime } from "../../src/adapters/microsandbox/runtime.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy, trivyPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { readScannerJson, type ScannerContext } from "../../src/scan/scanners/shared.js";
import { scanTrivy } from "../../src/scan/scanners/trivy.js";
import { makeReportInput } from "../support/findings.js";

const live = it.runIf(process.env.VIBESHIELD_LIVE_TRIVY === "1");
const layout = process.env.VIBESHIELD_TRIVY_TEST_LAYOUT ?? "installed";
async function scanFixture(context: ScannerContext) {
  // Detection fixtures use their review date; production freshness keeps the real clock.
  const clock = vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-07T12:00:00Z"));
  try {
    return await scanTrivy(context);
  } finally {
    clock.mockRestore();
  }
}

it.each([
  "2020-01-01T00:00:00Z",
  "2030-01-01T00:00:00Z",
])("fixture clock isolates detection acceptance from %s and restores the caller's time", async (wallTime) => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(wallTime));
  const runtime = new FakeSandboxRuntime();
  const session = await runtime.create({ name: "trivy-fixture-clock", imageTag: "fixture" });
  try {
    const raw = JSON.parse(
      await readFile(new URL("../fixtures/scanners/config/trivy.json", import.meta.url), "utf8"),
    );
    await session.uploadBytes(
      "/work/.vibeshield/exports/trivy.json",
      Buffer.from(JSON.stringify({ report: raw, bundle: trivyPolicy.bundle, warnings: false })),
    );
    const snapshot: Snapshot = {
      url: "https://github.com/fixture/config",
      commit: "a".repeat(40),
      files: ["vulnerable.yaml", "fixed.yaml"],
      languages: [],
      history: { commits: 1, truncated: false },
    };
    const ctx = { session, snapshot, signal: new AbortController().signal };
    const result = await scanFixture(ctx);
    expect(result.findings[0]?.ruleId).toBe("KSV-0017");
    expect(result.coverage.every((entry) => entry.status === "checked")).toBe(true);
    expect(Date.now()).toBe(Date.parse(wallTime));
    // Outside the fixture call, production still sees the caller's stale/invalid clock.
    expect((await scanTrivy(ctx)).coverage).toContainEqual(
      expect.objectContaining({ area: "check-bundle", status: "degraded" }),
    );
    await expect(
      scanFixture({ ...ctx, signal: AbortSignal.abort(new Error("fixture cancelled")) }),
    ).rejects.toThrow("fixture cancelled");
    expect(Date.now()).toBe(Date.parse(wallTime));
  } finally {
    vi.useRealTimers();
    await session.destroy();
  }
});
live(
  `pinned Trivy and bundle (${layout}) detect privileged pods, accept restricted pods, and reject missing checks`,
  async () => {
    const runtime = new MicrosandboxRuntime();
    const name = `vs-trivy-acceptance-${Date.now()}`;
    try {
      const session = await runtime.create({ name, imageTag: "vibeshield-toolchain:latest" });
      expect(["installed", "inject"]).toContain(layout);
      expect((await session.exec(["trivy", "--version"])).stdout.trim()).toBe("Version: 0.72.0");
      if ((await session.exec(["uname", "-m"])).stdout.trim() === "aarch64")
        expect(
          (await session.exec(["sha256sum", "/usr/local/bin/trivy"])).stdout.split(/\s+/)[0],
        ).toBe("829aca12d32bc3cee0b01cbb76197e9377790c6b78eb67a703d8033bcf7b3c3d");
      const files = [
        ["trivy.mjs", "/usr/local/bin/vibeshield-trivy"],
        ["trivy-manifest.json", "/opt/vibeshield/trivy/manifest.json"],
        ["export-results.mjs", "/usr/local/bin/export-results.mjs"],
        ["licenses/trivy-checks.LICENSE", "/opt/vibeshield/trivy/CHECKS-LICENSE"],
      ];
      for (const [local, remote] of files) {
        if (!local || !remote) throw new Error();
        const bytes = await readFile(new URL(`../../toolchain/${local}`, import.meta.url));
        if (layout === "inject" && (await session.exec(["test", "-e", remote])).exitCode === 1) {
          expect((await session.exec(["mkdir", "-p", dirname(remote)])).exitCode).toBe(0);
          await session.uploadBytes(remote, bytes);
        }
        expect(
          createHash("sha256")
            .update(await session.read(remote))
            .digest("hex"),
        ).toBe(createHash("sha256").update(bytes).digest("hex"));
      }
      if (layout === "inject") {
        const archive = process.env.VIBESHIELD_TRIVY_TEST_BUNDLE;
        if (!archive)
          throw new Error(
            "Set VIBESHIELD_TRIVY_TEST_BUNDLE to the exact digest-verified official bundle archive",
          );
        const bytes = await readFile(archive);
        expect(createHash("sha256").update(bytes).digest("hex")).toBe(
          "40a47ef8eb262c8e41d44f25c266463fff4dba9adcba12d33b93da88cbc7c80f",
        );
        await session.uploadBytes("/work/checks.tar.gz", bytes);
        // The preexisting image must not already contain a competing bundle.
        expect((await session.exec(["test", "-e", "/opt/vibeshield/trivy/cache"])).exitCode).toBe(
          1,
        );
        expect(
          (await session.exec(["mkdir", "-p", "/opt/vibeshield/trivy/cache/policy/content"]))
            .exitCode,
        ).toBe(0);
        expect(
          (
            await session.exec([
              "tar",
              "--no-same-owner",
              "-xzf",
              "/work/checks.tar.gz",
              "-C",
              "/opt/vibeshield/trivy/cache/policy/content",
            ])
          ).exitCode,
        ).toBe(0);
        await session.uploadBytes(
          "/opt/vibeshield/trivy/cache/policy/metadata.json",
          Buffer.from(
            JSON.stringify({
              Digest: "sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c",
              MajorVersion: 2,
            }),
          ),
        );
        await session.uploadBytes("/opt/vibeshield/trivy.yaml", Buffer.from("{}\n"));
        await session.uploadBytes("/opt/vibeshield/empty.ignore", Buffer.from(""));
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
      expect(
        (
          await session.exec([
            "mkdir",
            "-p",
            "/work/snapshot",
            "/work/.vibeshield/exports",
            "/work/.vibeshield/tmp",
          ])
        ).exitCode,
      ).toBe(0);
      for (const file of ["vulnerable.yaml", "fixed.yaml"])
        await session.uploadBytes(
          `/work/snapshot/${file}`,
          await readFile(new URL(`../fixtures/scanners/config/${file}`, import.meta.url)),
        );
      // Repository files must not choose rules, skip files, or inject commands.
      await session.uploadBytes(
        "/work/snapshot/trivy.yaml",
        Buffer.from("skip-files: [vulnerable.yaml]\nseverity: [LOW]\n"),
      );
      await session.uploadBytes(
        "/work/snapshot/.trivyignore",
        Buffer.from("KSV-0017\nAVD-KSV-0017\n"),
      );
      const snapshot: Snapshot = {
        url: "https://github.com/fixture/config",
        commit: "a".repeat(40),
        files: ["vulnerable.yaml", "fixed.yaml", "trivy.yaml", ".trivyignore"],
        languages: [],
        history: { commits: 1, truncated: false },
      };
      const ctx = { session, snapshot, signal: new AbortController().signal };
      const result = await scanFixture(ctx);
      console.log("Trivy acceptance", JSON.stringify(result));
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toMatchObject({
        ruleId: "KSV-0017",
        severity: "high",
        locations: [{ path: "vulnerable.yaml", line: 15 }],
      });
      expect(result.coverage.every((c) => c.status === "checked")).toBe(true);
      const report = buildReport({ ...makeReportInput([result]), policy: defaultPolicy });
      expect(report.issues).toHaveLength(1);
      expect(report.issues[0]?.remediation).toContain("privileged");
      const exported = (await readScannerJson(session, "/work/.vibeshield/exports/trivy.json")) as {
        report: {
          Results: { Target: string; Misconfigurations: { ID: string; Status: string }[] }[];
        };
      };
      const fixed = exported.report.Results.find((r) => r.Target === "fixed.yaml");
      expect(fixed?.Misconfigurations.find((m) => m.ID === "KSV-0017")?.Status).toBe("PASS");
      expect(fixed?.Misconfigurations.filter((m) => m.Status === "FAIL")).toEqual([]);
      const fixture = JSON.parse(
        await readFile(new URL("../fixtures/scanners/config/trivy.json", import.meta.url), "utf8"),
      );
      const selectedResults = exported.report.Results.filter((r) =>
        ["vulnerable.yaml", "fixed.yaml"].includes(r.Target),
      ).map((r) => ({
        ...r,
        Misconfigurations: r.Misconfigurations.filter((m) => m.ID === "KSV-0017"),
      }));
      expect(selectedResults.sort((a, b) => a.Target.localeCompare(b.Target))).toEqual(
        fixture.Results.sort((a: { Target: string }, b: { Target: string }) =>
          a.Target.localeCompare(b.Target),
        ),
      );
      // Each independent run receives a fresh create-once export/log location.
      async function rotate(label: string) {
        for (const file of ["exports/trivy.json", "trivy-log.txt"])
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
      await rotate("first");
      await session.uploadBytes(
        "/work/snapshot/vulnerable.yaml",
        Buffer.from("apiVersion: v1\nkind: Pod\nspec: [invalid\n"),
      );
      const malformed = await scanTrivy(ctx);
      expect(malformed.findings).toEqual([]);
      expect(
        buildReport({ ...makeReportInput([malformed]), policy: defaultPolicy }).incomplete,
      ).toBe(true);
      // Check actual command exit semantics separately: findings 9 when configured,
      // zero with --exit-code=0, invalid flags nonzero. Never use stdout for JSON.
      await session.uploadBytes(
        "/work/snapshot/vulnerable.yaml",
        await readFile(new URL("../fixtures/scanners/config/vulnerable.yaml", import.meta.url)),
      );
      await session.uploadBytes(
        "/work/exit-check.mjs",
        Buffer.from(`
      import { spawnSync } from 'node:child_process';
      import { trivyCommand } from '/usr/local/bin/vibeshield-trivy';
      import { gitEnvironment } from '/usr/local/bin/export-results.mjs';
      const status=spawnSync('trivy',trivyCommand().map(v=>v==='--exit-code=0'?'--exit-code=9':v),{cwd:'/work/.vibeshield',env:gitEnvironment(),stdio:'ignore'}).status;
      process.exitCode=status===9?0:1;
    `),
      );
      expect((await session.exec(["node", "/work/exit-check.mjs"])).exitCode).toBe(0);
      expect(
        (await session.exec(["trivy", "config", "--nonexistent-service-flag", "/work/snapshot"]))
          .exitCode,
      ).not.toBe(0);
      // Tampering a cached policy must fail before a fresh export appears.
      await rotate("malformed");
      await session.uploadBytes(
        "/opt/vibeshield/trivy/cache/policy/content/policies/kubernetes/policies/privileged.rego",
        Buffer.concat([
          await session.read(
            "/opt/vibeshield/trivy/cache/policy/content/policies/kubernetes/policies/privileged.rego",
          ),
          Buffer.from("\n# altered bytes\n"),
        ]),
      );
      const tampered = await scanTrivy(ctx);
      expect(tampered.findings).toEqual([]);
      expect(tampered.coverage[0]?.status).toBe("failed");
      expect(
        (await session.exec(["test", "-e", "/work/.vibeshield/exports/trivy.json"])).exitCode,
      ).toBe(1);
      expect(
        (
          await session.exec([
            "mv",
            "/opt/vibeshield/trivy/cache/policy/content",
            "/opt/vibeshield/trivy/absent-checks",
          ])
        ).exitCode,
      ).toBe(0);
      const missing = await scanTrivy(ctx);
      expect(missing.coverage[0]?.status).toBe("failed");
      expect(
        (await session.exec(["test", "-e", "/work/.vibeshield/exports/trivy.json"])).exitCode,
      ).toBe(1);
    } finally {
      await runtime.destroy(name);
      expect((await Sandbox.list()).some((item) => item.name === name)).toBe(false);
    }
  },
  180_000,
);
