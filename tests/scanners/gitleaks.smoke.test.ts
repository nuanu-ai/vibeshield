/** Real pinned scanner regressions; run with VIBESHIELD_LIVE_GITLEAKS=1. */
import { readFile } from "node:fs/promises";
import { Sandbox } from "microsandbox";
import { expect, it } from "vitest";
import { MicrosandboxRuntime } from "../../src/adapters/microsandbox/runtime.js";
import { validateAcquisition } from "../../src/scan/manifest.js";
import { scanGitleaks } from "../../src/scan/scanners/gitleaks.js";
import { readScannerJson } from "../../src/scan/scanners/shared.js";

const live = it.runIf(process.env.VIBESHIELD_LIVE_GITLEAKS === "1");
const fixture = `
import {spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,unlinkSync} from 'node:fs';
import {inventory} from '/usr/local/bin/vibeshield-acquire';
import {writeExport,gitEnvironment} from '/usr/local/bin/export-results.mjs';
const mode=process.argv[2];
for(const path of ['/work/.vibeshield','/work/.vibeshield/exports','/work/.vibeshield/tmp']) mkdirSync(path,{mode:0o700});
const git=(...args)=>{const result=spawnSync('git',['-C','/work/repository','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false',...args],{encoding:'utf8',stdio:['ignore','pipe','ignore']});if(result.status!==0) throw Error('Fixture Git failed');return result.stdout.trim();};
const init=spawnSync('git',['init','-q','-b','main','/work/repository'],{stdio:'ignore'});if(init.status!==0) throw Error('Fixture init failed');
const alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const token=()=> 'ghp_'+[...randomBytes(36)].map(value=>alphabet[value%alphabet.length]).join('');
let merge;
if(mode==='ignore') {
  writeFileSync('/work/repository/app.env','GITHUB_TOKEN='+token()+'\\n');
  // Learn the real pinned scanner fingerprint locally, never sending it to host.
  const baseline=spawnSync('gitleaks',['dir','/work/repository','--config=/opt/vibeshield/gitleaks.toml','--gitleaks-ignore-path=/opt/vibeshield/gitleaks.ignore','--redact=100','--exit-code=0','--report-format=json','--report-path=/work/.vibeshield/baseline.json'],{cwd:'/work/.vibeshield',env:gitEnvironment(),stdio:'ignore'});
  if(baseline.status!==0) throw Error('Fixture baseline failed');
  const found=JSON.parse(readFileSync('/work/.vibeshield/baseline.json','utf8'));
  if(found.length!==1) throw Error('Fixture baseline must detect one credential');
  // The acquired path differs from the repository staging path. Seed both actual
  // scanner-relative and absolute forms so path spelling cannot mask the bypass.
  const fingerprint=found[0].Fingerprint;
  const fingerprints=[fingerprint,fingerprint.replace('/work/repository/','/work/snapshot/'),fingerprint.replace('/work/repository/',''),fingerprint.replace('/work/repository/','tree/')];
  writeFileSync('/work/repository/.gitleaksignore',fingerprints.join('\\n')+'\\nGITHUB_TOKEN='+token()+'\\n');
  git('add','.');git('commit','-qm','synthetic ignore suppression');
} else {
  writeFileSync('/work/repository/merge.env','base\\n');git('add','.');git('commit','-qm','base');
  git('checkout','-qb','side');writeFileSync('/work/repository/merge.env','side\\n');git('commit','-qam','side');
  git('checkout','-q','main');writeFileSync('/work/repository/merge.env','main\\n');git('commit','-qam','main');
  const conflict=spawnSync('git',['-C','/work/repository','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','merge','--no-commit','side'],{stdio:'ignore'});
  if(conflict.status!==1) throw Error('Expected a real merge conflict');
  writeFileSync('/work/repository/merge.env','GITHUB_TOKEN='+token()+'\\n');git('add','.');git('commit','-qm','synthetic merge resolution');
  merge=git('rev-parse','HEAD');
  unlinkSync('/work/repository/merge.env');git('add','-A');git('commit','-qm','remove merge exposure');
  writeExport('/work/.vibeshield/exports/fixture.json',{merge});
}
writeExport('/work/.vibeshield/exports/snapshot.json',inventory('/work/repository','/work/snapshot','https://github.com/fixture/synthetic'));
`;

async function runFixture(mode: "ignore" | "merge") {
  const runtime = new MicrosandboxRuntime();
  const name = `vs-gitleaks-${mode}-${Date.now()}`;
  try {
    const session = await runtime.create({ name, imageTag: "vibeshield-toolchain:latest" });
    const version = await session.exec(["gitleaks", "version"]);
    expect(version.exitCode).toBe(0);
    expect(version.stdout.trim()).toBe("8.30.1");
    await session.uploadBytes(
      "/usr/local/bin/vibeshield-acquire",
      await readFile(new URL("../../toolchain/acquire.mjs", import.meta.url)),
    );
    await session.uploadBytes(
      "/usr/local/bin/export-results.mjs",
      await readFile(new URL("../../toolchain/export-results.mjs", import.meta.url)),
    );
    expect(
      (
        await session.exec([
          "sh",
          "-c",
          "ln -sf /usr/local/bin/export-results.mjs /usr/local/bin/vibeshield-export-results && mkdir -p /opt/vibeshield && touch /opt/vibeshield/gitleaks.ignore",
        ])
      ).exitCode,
    ).toBe(0);
    await session.uploadBytes(
      "/opt/vibeshield/gitleaks.toml",
      Buffer.from("[extend]\nuseDefault = true\n"),
    );
    await session.uploadBytes("/work/fixture.mjs", Buffer.from(fixture));
    const prepared = await session.exec(["node", "/work/fixture.mjs", mode]);
    expect(prepared.exitCode, "synthetic fixture preparation").toBe(0);
    const snapshot = validateAcquisition(
      await readScannerJson(session, "/work/.vibeshield/exports/snapshot.json"),
    ).snapshot;
    const result = await scanGitleaks({ session, snapshot, signal: new AbortController().signal });
    expect(result.coverage.every((area) => area.status === "checked")).toBe(true);
    if (mode === "ignore") {
      const currentPaths = result.findings.flatMap((finding) =>
        finding.locations.filter((location) => !location.commit).map((location) => location.path),
      );
      expect(currentPaths).toContain("app.env");
      expect(currentPaths).toContain(".gitleaksignore");
    } else {
      const metadata = (await readScannerJson(
        session,
        "/work/.vibeshield/exports/fixture.json",
      )) as { merge: string };
      expect(result.findings.flatMap((finding) => finding.locations)).toContainEqual({
        path: "merge.env",
        line: 1,
        commit: metadata.merge,
      });
      expect(snapshot.files).not.toContain("merge.env");
    }
  } finally {
    await runtime.destroy(name);
    expect((await Sandbox.list()).filter((entry) => entry.name === name)).toHaveLength(0);
  }
}

live(
  "tracked gitleaks ignore cannot suppress current findings or hide its own content",
  async () => {
    await runFixture("ignore");
  },
  60_000,
);
live(
  "merge-resolution-only exposure retains its merge commit and deleted path",
  async () => {
    await runFixture("merge");
  },
  60_000,
);
