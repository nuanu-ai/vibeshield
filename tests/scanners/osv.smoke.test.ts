import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Sandbox } from "microsandbox";
import { expect, it } from "vitest";
import { MicrosandboxRuntime } from "../../src/adapters/microsandbox/runtime.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { readOsvAdvisoryData, scanOsv } from "../../src/scan/scanners/osv.js";
import { readScannerJson } from "../../src/scan/scanners/shared.js";
import { makeReportInput } from "../support/findings.js";

const live = it.runIf(process.env.VIBESHIELD_LIVE_OSV === "1");
live(
  "official pinned OSV scans vulnerable/fixed lockfiles despite repository ignore policy",
  async () => {
    const runtime = new MicrosandboxRuntime();
    const name = `vs-osv-acceptance-${Date.now()}`;
    try {
      const session = await runtime.create({ name, imageTag: "vibeshield-toolchain:latest" });
      const arch = (await session.exec(["uname", "-m"])).stdout.trim();
      const hashes: Record<string, string> = {
        aarch64: "8158b18edd2d03b1a30d905ca91b032bc62262167be8f206c27114f08823e27c",
        x86_64: "bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc",
      };
      const files = [
        { path: "/usr/local/bin/vibeshield-osv", bytes: await readFile("toolchain/osv.mjs") },
        {
          path: "/usr/local/bin/export-results.mjs",
          bytes: await readFile("toolchain/export-results.mjs"),
        },
        { path: "/opt/vibeshield/osv.toml", bytes: Buffer.from("") },
      ];
      // Explicit disposable-VM development setup. Native image acceptance is the
      // default; missing or stale installed artifacts fail without this opt-in.
      const binaryPath = process.env.VIBESHIELD_OSV_BINARY;
      if (binaryPath) {
        const binary = await readFile(binaryPath);
        expect(createHash("sha256").update(binary).digest("hex")).toBe(hashes[arch]);
        const exists = await session.exec(["test", "-e", "/usr/local/bin/osv-scanner"]);
        if (exists.exitCode === 1) await session.uploadBytes("/usr/local/bin/osv-scanner", binary);
        for (const file of files) {
          const exists = await session.exec(["test", "-e", file.path]);
          if (exists.exitCode === 1) {
            expect(
              (await session.exec(["mkdir", "-p", file.path.slice(0, file.path.lastIndexOf("/"))]))
                .exitCode,
            ).toBe(0);
            await session.uploadBytes(file.path, file.bytes);
          }
        }
        expect((await session.exec(["chmod", "755", "/usr/local/bin/osv-scanner"])).exitCode).toBe(
          0,
        );
        if (
          (await session.exec(["test", "-L", "/usr/local/bin/vibeshield-export-results"]))
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
        (await session.exec(["sha256sum", "/usr/local/bin/osv-scanner"])).stdout.split(/\s+/)[0],
      ).toBe(hashes[arch]);
      for (const file of files) {
        const digest = (await session.exec(["sha256sum", file.path])).stdout.split(/\s+/)[0];
        expect(digest, file.path).toBe(createHash("sha256").update(file.bytes).digest("hex"));
      }
      const version = await session.exec(["osv-scanner", "--version"]);
      expect(version.exitCode).toBe(0);
      expect(version.stdout).toContain("osv-scanner version: 2.3.8\n");
      expect(version.stdout).toContain("408fcd6f8707999a29e7ba45e15809764cf24f67");
      expect(
        (
          await session.exec([
            "mkdir",
            "-p",
            "/work/.vibeshield/exports",
            "/work/.vibeshield/tmp",
            "/work/snapshot",
          ])
        ).exitCode,
      ).toBe(0);
      await session.uploadBytes("/work/snapshot/.gitignore", Buffer.from("package-lock.json\n"));
      await session.uploadBytes(
        "/work/snapshot/osv-scanner.toml",
        Buffer.from('[[PackageOverrides]]\nname = "lodash"\necosystem = "npm"\nignore = true\n'),
      );
      await session.uploadBytes(
        "/work/snapshot/package.json",
        Buffer.from(
          JSON.stringify({
            scripts: { preinstall: "touch /work/TARGET_EXECUTED" },
            devDependencies: { lodash: "^4.17.0" },
          }),
        ),
      );
      await session.uploadBytes(
        "/work/snapshot/osv-scanner-custom.json",
        Buffer.from('{"results": "malicious non-lockfile input"}'),
      );
      const snapshot: Snapshot = {
        url: "https://github.com/fixture/dependencies",
        commit: "a".repeat(40),
        files: [
          "package-lock.json",
          "package.json",
          ".gitignore",
          "osv-scanner.toml",
          "osv-scanner-custom.json",
        ],
        languages: ["JavaScript"],
        history: { commits: 1, truncated: false },
        oversized: 0,
      };
      for (const fixture of ["vulnerable", "fixed"] as const) {
        await session.uploadBytes(
          "/work/.vibeshield/exports/snapshot.json",
          Buffer.from(JSON.stringify({ snapshot })),
        );
        await session.uploadBytes(
          "/work/snapshot/package-lock.json",
          await readFile(`tests/fixtures/scanners/dependencies/${fixture}/package-lock.json`),
        );
        const result = await scanOsv({ session, snapshot, signal: new AbortController().signal });
        const raw = await readScannerJson(session, "/work/.vibeshield/exports/osv.json");
        expect(raw).toMatchObject({
          scannerVersion: "2.3.8",
          exitCode: fixture === "vulnerable" ? 1 : 0,
          diagnostics: false,
        });
        expect(result.coverage).toEqual([
          expect.objectContaining({
            area: "package-lock.json",
            status: "checked",
            applicable: true,
          }),
        ]);
        const advisoryData = await readOsvAdvisoryData(session);
        expect(advisoryData).toMatchObject({ source: "OSV", stale: false });
        expect(advisoryData).not.toHaveProperty("revision");
        const report = buildReport({ ...makeReportInput([result]), policy: defaultPolicy });
        if (fixture === "vulnerable") {
          expect(result.findings.length).toBeGreaterThan(0);
          expect(
            result.findings.every(
              (x) => x.dependency?.version === "4.17.20" && x.dependency.scope === "development",
            ),
          ).toBe(true);
          expect(
            result.findings.some((x) => x.dependency?.advisoryIds.includes("CVE-2021-23337")),
          ).toBe(true);
          expect(report.issues.length).toBeGreaterThan(0);
        } else {
          expect(result.findings).toEqual([]);
          expect(report.issues).toEqual([]);
        }
        console.log(
          JSON.stringify({
            fixture,
            findings: result.findings.length,
            issues: report.issues.length,
            coverage: result.coverage,
            advisoryData,
          }),
        );
        expect(
          (
            await session.exec([
              "mv",
              "/work/.vibeshield/exports/osv.json",
              `/work/.vibeshield/${fixture}-osv.json`,
            ])
          ).exitCode,
        ).toBe(0);
      }
      expect((await session.exec(["test", "-e", "/work/TARGET_EXECUTED"])).exitCode).toBe(1);
      expect((await session.exec(["test", "-d", "/work/snapshot/node_modules"])).exitCode).toBe(1);
      // A malformed second lockfile must not vanish behind exit 1 from the first.
      await session.uploadBytes(
        "/work/snapshot/package-lock.json",
        await readFile("tests/fixtures/scanners/dependencies/vulnerable/package-lock.json"),
      );
      expect((await session.exec(["mkdir", "-p", "/work/snapshot/broken"])).exitCode).toBe(0);
      await session.uploadBytes("/work/snapshot/broken/package-lock.json", Buffer.from("{"));
      const partialSnapshot = {
        ...snapshot,
        files: [...snapshot.files, "broken/package-lock.json"],
      };
      await session.uploadBytes(
        "/work/.vibeshield/exports/snapshot.json",
        Buffer.from(JSON.stringify({ snapshot: partialSnapshot })),
      );
      const partial = await scanOsv({
        session,
        snapshot: partialSnapshot,
        signal: new AbortController().signal,
      });
      expect(partial.findings.length).toBeGreaterThan(0);
      expect(partial.coverage).toContainEqual(
        expect.objectContaining({ area: "broken/package-lock.json", status: "degraded" }),
      );
      expect(partial.coverage.some((x) => x.status !== "checked")).toBe(true);
      expect(await readScannerJson(session, "/work/.vibeshield/exports/osv.json")).toMatchObject({
        exitCode: 1,
        diagnostics: true,
      });
      expect(
        (
          await session.exec([
            "mv",
            "/work/.vibeshield/exports/osv.json",
            "/work/.vibeshield/partial-osv.json",
          ])
        ).exitCode,
      ).toBe(0);
      expect(
        (await session.exec(["mv", "/work/snapshot", "/work/.vibeshield/npm-snapshot"])).exitCode,
      ).toBe(0);
      expect((await session.exec(["mkdir", "-p", "/work/snapshot/packages/app"])).exitCode).toBe(0);
      await session.uploadBytes(
        "/work/snapshot/package.json",
        Buffer.from(
          JSON.stringify({ name: "workspace-root", private: true, workspaces: ["packages/*"] }),
        ),
      );
      await session.uploadBytes(
        "/work/snapshot/packages/app/package.json",
        Buffer.from(JSON.stringify({ name: "workspace-app", dependencies: { lodash: "^4.17.0" } })),
      );
      await session.uploadBytes(
        "/work/snapshot/yarn.lock",
        Buffer.from('# yarn lockfile v1\n\nlodash@^4.17.0:\n  version "4.18.0"\n'),
      );
      const workspaceSnapshot: Snapshot = {
        ...snapshot,
        files: ["package.json", "packages/app/package.json", "yarn.lock"],
      };
      await session.uploadBytes(
        "/work/.vibeshield/exports/snapshot.json",
        Buffer.from(JSON.stringify({ snapshot: workspaceSnapshot })),
      );
      const workspace = await scanOsv({
        session,
        snapshot: workspaceSnapshot,
        signal: new AbortController().signal,
      });
      expect(await readScannerJson(session, "/work/.vibeshield/exports/osv.json")).toMatchObject({
        exitCode: 0,
        diagnostics: false,
        workspaceMembers: [{ manifest: "packages/app/package.json", lockfile: "yarn.lock" }],
        output: {
          results: [
            {
              source: { path: "/work/snapshot/yarn.lock" },
              packages: [{ package: { name: "lodash", version: "4.18.0" } }],
            },
          ],
        },
      });
      expect(workspace.coverage).toEqual([
        expect.objectContaining({ area: "yarn.lock", status: "checked" }),
      ]);
      expect(
        buildReport({ ...makeReportInput([workspace]), policy: defaultPolicy }).incomplete,
      ).toBe(false);
      expect(
        (
          await session.exec([
            "mv",
            "/work/.vibeshield/exports/osv.json",
            "/work/.vibeshield/workspace-osv.json",
          ])
        ).exitCode,
      ).toBe(0);
      expect((await session.exec(["mkdir", "-p", "/work/snapshot/independent"])).exitCode).toBe(0);
      await session.uploadBytes(
        "/work/snapshot/independent/package.json",
        Buffer.from(JSON.stringify({ name: "independent", dependencies: { lodash: "^4.17.0" } })),
      );
      workspaceSnapshot.files.push("independent/package.json");
      await session.uploadBytes(
        "/work/.vibeshield/exports/snapshot.json",
        Buffer.from(JSON.stringify({ snapshot: workspaceSnapshot })),
      );
      const independent = await scanOsv({
        session,
        snapshot: workspaceSnapshot,
        signal: new AbortController().signal,
      });
      expect(independent.coverage).toContainEqual(
        expect.objectContaining({
          area: "independent/package.json",
          status: "skipped",
          applicable: true,
        }),
      );
      expect(
        buildReport({ ...makeReportInput([independent]), policy: defaultPolicy }).incomplete,
      ).toBe(true);
      expect(await readScannerJson(session, "/work/.vibeshield/exports/osv.json")).toMatchObject({
        exitCode: 0,
        diagnostics: false,
        workspaceMembers: [{ manifest: "packages/app/package.json", lockfile: "yarn.lock" }],
      });
      console.log(
        JSON.stringify({
          fixture: "yarn-workspace",
          workspace: workspace.coverage,
          independent: independent.coverage,
        }),
      );
      expect(
        (
          await session.exec([
            "mv",
            "/work/.vibeshield/exports/osv.json",
            "/work/.vibeshield/yarn-independent-osv.json",
          ])
        ).exitCode,
      ).toBe(0);
      expect(
        (await session.exec(["mv", "/work/snapshot", "/work/.vibeshield/yarn-snapshot"])).exitCode,
      ).toBe(0);
      expect((await session.exec(["mkdir", "-p", "/work/snapshot/independent"])).exitCode).toBe(0);
      await session.uploadBytes(
        "/work/snapshot/package.json",
        Buffer.from(
          JSON.stringify({
            name: "pnpm-root",
            private: true,
            dependencies: { lodash: "^4.17.0" },
          }),
        ),
      );
      await session.uploadBytes(
        "/work/snapshot/pnpm-lock.yaml",
        Buffer.from(
          "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n        version: 4.18.0\npackages:\n  lodash@4.18.0:\n    resolution: {}\nsnapshots:\n  lodash@4.18.0: {}\n",
        ),
      );
      const pnpmSnapshot: Snapshot = {
        ...snapshot,
        files: [
          "package.json",
          "independent/package.json",
          "pnpm-lock.yaml",
          "pnpm-workspace.yaml",
        ],
      };
      await session.uploadBytes(
        "/work/.vibeshield/exports/snapshot.json",
        Buffer.from(JSON.stringify({ snapshot: pnpmSnapshot })),
      );
      for (const [label, scalar, covered] of [
        ["alias", "*", false],
        ["double-alias", "**", false],
        ["quoted-space", '" independent "', false],
        ["quoted-glob", '"*"', true],
      ] as const) {
        await session.uploadBytes(
          "/work/snapshot/independent/package.json",
          Buffer.from(
            JSON.stringify({
              name: "independent",
              dependencies: covered ? { lodash: "^4.17.0" } : { axios: "^0.21.0" },
            }),
          ),
        );
        await session.uploadBytes(
          "/work/snapshot/pnpm-workspace.yaml",
          Buffer.from(`packages:\n  - ${scalar}\n`),
        );
        const result = await scanOsv({
          session,
          snapshot: pnpmSnapshot,
          signal: new AbortController().signal,
        });
        const raw = await readScannerJson(session, "/work/.vibeshield/exports/osv.json");
        expect(raw).toMatchObject({
          exitCode: 0,
          diagnostics: false,
          output: {
            results: [
              {
                source: { path: "/work/snapshot/pnpm-lock.yaml" },
                packages: [{ package: { name: "lodash", version: "4.18.0" } }],
              },
            ],
          },
        });
        expect.soft(raw).toMatchObject({
          workspaceMembers: covered
            ? [{ manifest: "independent/package.json", lockfile: "pnpm-lock.yaml" }]
            : [],
        });
        expect.soft(result.coverage).toEqual([
          expect.objectContaining({ area: "pnpm-lock.yaml", status: "checked" }),
          ...(covered
            ? []
            : [
                expect.objectContaining({
                  area: "independent/package.json",
                  status: "skipped",
                  applicable: true,
                }),
              ]),
        ]);
        const report = buildReport({ ...makeReportInput([result]), policy: defaultPolicy });
        expect.soft(report.incomplete).toBe(!covered);
        console.log(
          JSON.stringify({
            fixture: `pnpm-${label}`,
            coverage: result.coverage,
            incomplete: report.incomplete,
          }),
        );
        expect(
          (
            await session.exec([
              "mv",
              "/work/.vibeshield/exports/osv.json",
              `/work/.vibeshield/pnpm-${label}-osv.json`,
            ])
          ).exitCode,
        ).toBe(0);
      }
    } finally {
      await runtime.destroy(name);
      expect((await Sandbox.list()).filter((x) => x.name === name)).toHaveLength(0);
    }
  },
  120000,
);
