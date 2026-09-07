import { expect, it } from "vitest";
import type { ScannerId, ScanResult } from "../../src/scan/contracts.js";
import { defaultPolicy } from "../../src/scan/policy.js";
import { buildReport } from "../../src/scan/report.js";
import { scanGitleaks } from "../../src/scan/scanners/gitleaks.js";
import { scanOpengrep } from "../../src/scan/scanners/opengrep.js";
import { readOsvAdvisoryData, scanOsv } from "../../src/scan/scanners/osv.js";
import { readScannerJson, type ScannerContext } from "../../src/scan/scanners/shared.js";
import { scanTrivy } from "../../src/scan/scanners/trivy.js";
import { scanZizmor } from "../../src/scan/scanners/zizmor.js";
import { createLiveFixtures, selectLiveFixture } from "../support/live-fixtures.js";
import {
  assertOwnedCleanup,
  saveEvidence,
  verifyLivePrerequisites,
  withLiveSession,
} from "../support/live-runtime.js";

const scanners: [ScannerId, (context: ScannerContext) => Promise<ScanResult>][] = [
  ["gitleaks", scanGitleaks],
  ["opengrep", scanOpengrep],
  ["osv", scanOsv],
  ["trivy", scanTrivy],
  ["zizmor", scanZizmor],
];
const selectedCodeRules = [
  "rules_lgpl_javascript_exec_rule-shelljs-os-command-exec",
  "rules_lgpl_javascript_database_rule-node-sqli-injection",
  "rules_lgpl_javascript_traversal_rule-express-lfr",
  "rules_lgpl_javascript_ssrf_rule-node-ssrf",
  "rules_lgpl_javascript_eval_rule-node-deserialize",
  "rules_lgpl_javascript_jwt_rule-node-jwt-none-algorithm",
].sort();

it("runs all five installed engines on vulnerable, fixed and clean controls and publishes actual evidence", async () => {
  const provenance = await verifyLivePrerequisites();
  await withLiveSession("controls", async (session) => {
    await createLiveFixtures(session);
    const upstream = await session.exec(
      ["opengrep", "scan", "--test", "--no-rewrite-rule-ids", "/work/upstream-tests"],
      {
        timeoutMs: 120000,
        env: { HOME: "/opt/vibeshield/opengrep-home" },
        maxFileBytes: 10 * 1024 * 1024,
      },
    );
    expect(upstream.exitCode, "all six pinned upstream rule annotation controls must pass").toBe(0);
    expect(upstream.stdout).toContain("All tests passed");
    await saveEvidence("upstream-rules", { passed: true, rules: selectedCodeRules });
    for (const variant of ["vulnerable", "fixed", "clean", "warnings"] as const) {
      const snapshot = await selectLiveFixture(session, variant);
      const context = { session, snapshot, signal: new AbortController().signal };
      const results: ScanResult[] = [];
      const scanProvenance = structuredClone(provenance);
      for (const [id, scan] of scanners) {
        const result = await scan(context);
        results.push(result);
        await saveEvidence(`${variant}-${id}`, result);
        expect(
          result.coverage.some((coverage) => coverage.applicable),
          `${variant}: ${id} must run`,
        ).toBe(true);
        if (variant !== "warnings") {
          expect(
            result.coverage.some((coverage) => coverage.status === "failed"),
            `${variant}: ${id} failed`,
          ).toBe(false);
          expect(
            result.coverage.some((coverage) => coverage.status === "checked"),
            `${variant}: ${id} never completed`,
          ).toBe(true);
        }
        if (variant === "vulnerable") {
          expect(
            result.findings.length,
            `${id} must detect its selected vulnerable fixture`,
          ).toBeGreaterThan(0);
          if (id === "gitleaks") {
            const historical = await session.exec([
              "git",
              "-C",
              "/work/repository",
              "rev-parse",
              "HEAD^",
            ]);
            expect(historical.exitCode).toBe(0);
            const historicalCommit = historical.stdout.trim();
            expect(historicalCommit).toMatch(/^[a-f0-9]{40}$/);
            expect(historicalCommit).not.toBe(snapshot.commit);
            expect(snapshot.files).not.toContain("historical.env");
            expect(
              result.findings.some((finding) =>
                finding.locations.some(
                  (location) => location.path === "current.env" && !location.commit,
                ),
              ),
            ).toBe(true);
            expect(
              result.findings.some((finding) =>
                finding.locations.some(
                  (location) =>
                    location.path === "historical.env" && location.commit === historicalCommit,
                ),
              ),
            ).toBe(true);
            for (const mode of ["current", "history"]) {
              const exported = await readScannerJson(
                session,
                `/work/.vibeshield/exports/gitleaks-${mode}.json`,
              );
              expect(JSON.stringify(exported)).not.toMatch(/ghp_|Secret|Match/);
            }
            const redaction = await session.exec([
              "node",
              "--input-type=module",
              "-e",
              "import{readFileSync}from'node:fs';import{execFileSync}from'node:child_process';import{gitEnvironment}from'/usr/local/bin/export-results.mjs';const secrets=[readFileSync('/work/snapshot/current.env','utf8'),execFileSync('git',['-C','/work/repository','show','HEAD^:historical.env'],{env:gitEnvironment(),encoding:'utf8'})].map(value=>value.trim().split('=')[1]);const exports=['current','history'].map(mode=>readFileSync('/work/.vibeshield/exports/gitleaks-'+mode+'.json','utf8'));if(secrets.length!==2||secrets.some(value=>value.length!==36||exports.some(raw=>raw.includes(value))))process.exit(1);console.log('Both generated secret values are absent from exports');",
            ]);
            expect(redaction.exitCode).toBe(0);
            expect(redaction.stdout).toContain("Both generated secret values are absent");
          }
          if (id === "opengrep")
            expect([...new Set(result.findings.map((finding) => finding.ruleId))].sort()).toEqual(
              selectedCodeRules,
            );
          if (id === "osv") {
            expect(
              result.findings.every(
                (finding) =>
                  finding.dependency?.version === "4.17.20" &&
                  finding.dependency.manifest === "package-lock.json",
              ),
            ).toBe(true);
            expect(
              result.findings.some((finding) =>
                finding.dependency?.advisoryIds.includes("CVE-2021-23337"),
              ),
            ).toBe(true);
            expect(await readOsvAdvisoryData(session)).toMatchObject({
              source: "OSV",
              stale: false,
            });
          }
          if (id === "trivy")
            expect(result.findings.some((finding) => finding.ruleId === "KSV-0017")).toBe(true);
          if (id === "zizmor")
            expect(result.findings.some((finding) => finding.ruleId === "template-injection")).toBe(
              true,
            );
        } else if (variant !== "warnings") {
          expect(result.findings, `${id} must lose the selected finding in ${variant}`).toEqual([]);
        }
        if (id === "osv") {
          const advisoryData = await readOsvAdvisoryData(session);
          await saveEvidence(`${variant}-advisory-data`, advisoryData ?? { unavailable: true });
          if (advisoryData) scanProvenance.advisoryData.push(advisoryData);
        }
      }
      const report = buildReport({
        repository: snapshot,
        provenance: scanProvenance,
        generatedAt: new Date().toISOString(),
        results,
        policy: defaultPolicy,
      });
      await saveEvidence(`${variant}-report`, report);
      expect(JSON.stringify(report)).not.toMatch(/ghp_|TARGET_EXECUTED/);
      if (variant === "vulnerable" || variant === "warnings") {
        for (const [id] of scanners)
          expect(
            report.issues.some((issue) =>
              issue.findingIds.some((finding) => finding.startsWith(`${id}:`)),
            ),
            `${id} finding must reach publication`,
          ).toBe(true);
        expect(
          report.issues.every((issue) => issue.prompt.length > 0 && issue.verification.length > 0),
        ).toBe(true);
        expect(
          report.issues.some(
            (issue) =>
              issue.locations.some((location) => location.path === "historical.env") &&
              /rotat|revok/i.test(issue.prompt),
          ),
        ).toBe(true);
      } else expect(report.issues).toEqual([]);
      if (variant === "warnings") {
        expect(report.incomplete).toBe(true);
        for (const id of ["opengrep", "osv", "trivy"])
          expect(
            report.coverage.some(
              (entry) => entry.scanner === id && ["degraded", "failed"].includes(entry.status),
            ),
            `${id} parser warning must remain visible`,
          ).toBe(true);
        expect(await readOsvAdvisoryData(session)).toBeUndefined();
        expect(
          await readScannerJson(session, "/work/.vibeshield/exports/trivy.json"),
        ).toMatchObject({ warnings: true });
        expect(report.coverage).toContainEqual(
          expect.objectContaining({ scanner: "trivy", area: "kubernetes", status: "degraded" }),
        );
        expect(await readScannerJson(session, "/work/.vibeshield/exports/osv.json")).toMatchObject({
          diagnostics: true,
        });
      }
      expect((await session.exec(["test", "-e", "/work/TARGET_EXECUTED"])).exitCode).toBe(1);
      expect((await session.exec(["test", "-d", "/work/snapshot/node_modules"])).exitCode).toBe(1);
    }
  });
  await assertOwnedCleanup();
});

it("stops a timed-out scanner process tree, rejects output overflow and removes its VM", async () => {
  await withLiveSession("limits", async (session) => {
    const timed = await session.exec(
      [
        "node",
        "-e",
        "const fs=require('fs'); const child=require('child_process').spawn('sleep',['60'],{stdio:'inherit'});fs.writeFileSync('/work/pids.json',JSON.stringify([process.pid,child.pid]));setInterval(()=>{},1000)",
      ],
      { timeoutMs: 2000 },
    );
    expect(timed.exitCode).toBe(124);
    const alive = await session.exec([
      "node",
      "-e",
      "const fs=require('fs');const pids=JSON.parse(fs.readFileSync('/work/pids.json'));const alive=pids.filter(pid=>{try {const state=fs.readFileSync('/proc/'+pid+'/stat','utf8').split(' ')[2];return state!=='Z'}catch{return false}});console.log(JSON.stringify(alive))",
    ]);
    expect(JSON.parse(alive.stdout)).toEqual([]);
    const control = await session.exec(
      [
        "node",
        "-e",
        "require('fs').writeFileSync('/work/below-limit.json',Buffer.alloc(10*1024*1024))",
      ],
      { timeoutMs: 10000, maxFileBytes: 10 * 1024 * 1024 },
    );
    expect(control.exitCode).toBe(0);
    const controlSize = await session.exec(["stat", "-c", "%s", "/work/below-limit.json"]);
    expect(controlSize.exitCode).toBe(0);
    expect(Number(controlSize.stdout.trim())).toBe(10 * 1024 * 1024);
    for (const mode of ["file", "stdout"] as const) {
      const output = `/work/${mode}-overflow.json`;
      const command =
        mode === "file"
          ? `require('fs').writeFileSync('${output}',Buffer.alloc(12*1024*1024))`
          : "process.stdout.write(Buffer.alloc(12*1024*1024))";
      const result = await session.exec(["node", "-e", command], {
        timeoutMs: 10000,
        maxFileBytes: 10 * 1024 * 1024,
        ...(mode === "stdout" ? { stdoutPath: output } : {}),
      });
      expect(result.exitCode).not.toBe(0);
      const size = await session.exec(["stat", "-c", "%s", output]);
      expect(size.exitCode).toBe(0);
      expect(Number(size.stdout.trim())).toBeGreaterThan(0);
      expect(Number(size.stdout.trim())).toBeLessThanOrEqual(10 * 1024 * 1024);
    }
    await saveEvidence("resource-limits", {
      timeoutExit: timed.exitCode,
      liveDescendants: [],
      maxScannerBytes: 10485760,
      overflowModesFailed: ["file", "stdout"],
    });
  });
  await assertOwnedCleanup();
});
