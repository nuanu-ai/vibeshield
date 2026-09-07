import { readFileSync } from "node:fs";
import { FakeSandboxRuntime, type FakeSandboxSession } from "../../src/adapters/fake-sandbox.js";
import type { SandboxCreateOptions } from "../../src/ports/sandbox-runtime.js";
import type { Provenance, ScannerId, Snapshot } from "../../src/scan/contracts.js";
import type { Clock } from "../../src/web/clock.js";

export const engines: ScannerId[] = ["gitleaks", "opengrep", "osv", "trivy", "zizmor"];
export const privateText = "synthetic-credential-graph-model-metadata-never-export";
export const fixtureProvenance: Provenance = {
  image: "vibeshield-toolchain:fixture",
  tools: {
    gitleaks: "8.30.0",
    opengrep: "1.25.0",
    osv: "2.3.8",
    trivy: "0.72.0",
    zizmor: "1.30.0",
  },
  rulesRevision: "fixture-revision",
  advisoryData: [
    { source: "frozen-checks", retrievedAt: "2026-09-07T00:00:00.000Z", stale: false },
  ],
};
export const fixtureSnapshot: Snapshot = {
  url: "https://github.com/owner/repo",
  commit: "a".repeat(40),
  files: [
    "app.ts",
    "package-lock.json",
    "vulnerable.yaml",
    "fixed.yaml",
    ".github/workflows/vulnerable.yml",
    ".github/workflows/fixed.yml",
  ],
  languages: ["TypeScript"],
  history: { commits: 1, truncated: false },
};
function fixture(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`../fixtures/scanners/${name}`, import.meta.url), "utf8"));
}
export function rawOsv() {
  return {
    scannerVersion: "2.3.8",
    exitCode: 1,
    diagnostics: false,
    workspaceMembers: [],
    advisoryData: { source: "OSV", retrievedAt: "2026-09-07T12:00:00.000Z", stale: false },
    output: {
      results: [
        {
          source: { path: "/work/snapshot/package-lock.json", type: "lockfile" },
          packages: [
            {
              package: { name: "lodash", version: "4.17.20", ecosystem: "npm" },
              dependency_groups: ["dev"],
              vulnerabilities: [
                {
                  id: "GHSA-fixture",
                  aliases: ["CVE-2026-1234"],
                  summary: "Known vulnerable lodash",
                  database_specific: { severity: "HIGH" },
                  affected: [
                    {
                      package: { ecosystem: "npm", name: "lodash" },
                      ranges: [
                        { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
    securityGraph: privateText,
    modelMetadata: privateText,
  };
}
function rawOpengrep() {
  const id = "rules_lgpl_javascript_ssrf_rule-node-ssrf";
  const location = (line: number) => ({
    physicalLocation: {
      artifactLocation: { uri: "app.ts" },
      region: { startLine: line, snippet: { text: privateText } },
    },
  });
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Opengrep OSS",
            semanticVersion: "1.25.0",
            rules: [
              id,
              "rules_lgpl_javascript_exec_rule-shelljs-os-command-exec",
              "rules_lgpl_javascript_database_rule-node-sqli-injection",
              "rules_lgpl_javascript_traversal_rule-express-lfr",
              "rules_lgpl_javascript_eval_rule-node-deserialize",
              "rules_lgpl_javascript_jwt_rule-node-jwt-none-algorithm",
            ].map((id) => ({
              id,
              shortDescription: { text: "Untrusted request destination" },
              properties: { "security-severity": "HIGH" },
            })),
          },
        },
        invocations: [{ executionSuccessful: true }],
        results: [
          {
            ruleId: id,
            message: { text: privateText },
            locations: [location(5)],
            codeFlows: [
              {
                threadFlows: [
                  { locations: [{ location: location(2) }, { location: location(5) }] },
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}
export function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

/** Controls raw guest exports and command completion, never scanner/report decisions. */
export class ControlledSandbox extends FakeSandboxRuntime {
  readonly outputs = new Map<string, unknown>([
    [
      "gitleaks-current",
      [{ ruleId: "generic-api-key", path: "app.ts", line: 1, fingerprint: "b".repeat(64) }],
    ],
    ["gitleaks-history", []],
    ["opengrep", rawOpengrep()],
    ["osv", rawOsv()],
    [
      "trivy",
      {
        report: fixture("config/trivy.json"),
        bundle: {
          digest: "sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c",
          revision: "d7c9302130a9b7e614a5c5d32854f6a08b4bc52e",
          version: "2.2.0",
          reviewedAt: "2026-09-07T00:00:00Z",
        },
        warnings: false,
      },
    ],
    [
      "zizmor",
      {
        version: "1.30.0",
        offline: true,
        warnings: false,
        selectedAudits: ["template-injection"],
        files: fixtureSnapshot.files.filter((path) => path.startsWith(".github/")),
        findings: fixture("workflows/zizmor.json"),
      },
    ],
  ]);
  readonly started: ScannerId[] = [];
  readonly created: SandboxCreateOptions[] = [];
  readonly destroyed: string[] = [];
  readonly gates = new Map(engines.map((id) => [id, deferred()]));
  readonly failures = new Map<ScannerId, number>();
  snapshot = structuredClone(fixtureSnapshot);
  acquisitionFails = false;
  cleanupFails = false;
  cleanupGate: ReturnType<typeof deferred> | undefined;
  beforeExport: ((key: string) => void) | undefined;
  beforeRead: ((path: string) => Promise<void>) | undefined;
  constructor() {
    super({
      exec: async (command, session) => {
        const bin = command[1];
        if (bin === "/usr/local/bin/vibeshield-acquire") {
          if (this.acquisitionFails)
            return { exitCode: 128, stdout: privateText, stderr: privateText };
          const snapshot = { ...this.snapshot, url: command[2] };
          await this.export(session, "snapshot", {
            snapshot,
            entries: snapshot.files.map((path) => ({ path, size: 10, kind: "file" })),
            fetchedCommits: [snapshot.commit],
            rawCredential: privateText,
          });
        } else if (command[2] !== "verify") {
          const engine =
            bin === "/usr/local/bin/vibeshield-export-results"
              ? "gitleaks"
              : engines.find((id) => bin === `/usr/local/bin/vibeshield-${id}`);
          if (!engine) throw new Error("Unexpected command in controlled sandbox");
          if (this.started.at(-1) !== engine) this.started.push(engine);
          await this.gates.get(engine)?.promise;
          if (this.failures.has(engine))
            return {
              exitCode: this.failures.get(engine) ?? 1,
              stdout: privateText,
              stderr: privateText,
            };
          const key = engine === "gitleaks" ? `gitleaks-${command[3]}` : engine;
          this.beforeExport?.(key);
          await this.export(session, key, this.outputs.get(key));
        }
        return { exitCode: 0, stdout: privateText, stderr: privateText };
      },
    });
  }
  private async export(session: FakeSandboxSession, key: string, value: unknown) {
    await session.uploadBytes(
      `/work/.vibeshield/exports/${key}.json`,
      Buffer.from(typeof value === "string" ? value : JSON.stringify(value)),
    );
  }
  override async create(options: SandboxCreateOptions) {
    this.created.push(options);
    const session = await super.create(options);
    const read = session.read.bind(session);
    session.read = async (path) => {
      await this.beforeRead?.(path);
      return read(path);
    };
    return session;
  }
  release(engine: ScannerId): void {
    this.gates.get(engine)?.resolve();
  }
  releaseAll(): void {
    for (const engine of engines) this.release(engine);
  }
  fail(engine: ScannerId): void {
    this.failures.set(engine, 1);
    this.release(engine);
  }
  override async destroy(name: string): Promise<void> {
    this.destroyed.push(name);
    await this.cleanupGate?.promise;
    if (this.cleanupFails) throw new Error(privateText);
    await super.destroy(name);
  }
  async cleanup(): Promise<void> {
    for (const name of this.sessions.keys()) await this.destroy(name);
  }
}

export class ManualClock implements Clock {
  private time = Date.parse("2026-09-07T12:00:00.000Z");
  private sequence = 0;
  private readonly timers = new Map<number, { at: number; callback: () => void }>();
  now(): number {
    return this.time;
  }
  schedule(delayMs: number, callback: () => void): () => void {
    const id = this.sequence++;
    this.timers.set(id, { at: this.time + delayMs, callback });
    return () => {
      this.timers.delete(id);
    };
  }
  advance(ms: number): void {
    const end = this.time + ms;
    for (;;) {
      const next = [...this.timers.entries()]
        .filter(([, timer]) => timer.at <= end)
        .sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
      if (!next) break;
      this.time = Math.max(this.time, next[1].at);
      this.timers.delete(next[0]);
      next[1].callback();
    }
    this.time = end;
  }
  /** Simulate an event-loop stall: wall time moves but callbacks have not run. */
  jump(ms: number): void {
    this.time += ms;
  }
  pending(): number {
    return this.timers.size;
  }
}
