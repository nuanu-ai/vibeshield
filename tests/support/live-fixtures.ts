import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { SandboxSession } from "../../src/ports/sandbox-runtime.js";
import type { Snapshot } from "../../src/scan/contracts.js";
import { validateAcquisition } from "../../src/scan/manifest.js";
import { readScannerJson } from "../../src/scan/scanners/shared.js";

export type LiveFixtureVariant = "vulnerable" | "fixed" | "clean" | "warnings";

const scripts = new WeakMap<SandboxSession, string>();
const snapshotExport = "/work/.vibeshield/exports/snapshot.json";

/**
 * Prepare service-owned inputs in a fresh live guest and select vulnerable input.
 * This helper never runs target code, installs dependencies, or uses local intake.
 * Selected upstream rule tests are placed separately at /work/upstream-tests.
 */
export async function createLiveFixtures(session: SandboxSession): Promise<void> {
  if (scripts.has(session)) throw new Error("Live fixtures already initialized for this session");
  const inputs = [
    "code/vulnerable.ts",
    "code/fixed.ts",
    "code/clean.ts",
    "dependencies/vulnerable/package-lock.json",
    "dependencies/fixed/package-lock.json",
    "config/vulnerable.yaml",
    "config/fixed.yaml",
    "workflows/vulnerable.yml",
    "workflows/fixed.yml",
  ];
  const fixtures = Object.fromEntries(
    await Promise.all(
      inputs.map(async (path) => [
        path,
        await readFile(new URL(`../fixtures/scanners/${path}`, import.meta.url), "utf8"),
      ]),
    ),
  );
  const script = `/run/vibeshield-live-fixtures-${randomUUID()}.mjs`;
  await session.uploadBytes(
    script,
    Buffer.from(`const fixtures = ${JSON.stringify(fixtures)};\n${guestFixtureScript}`),
  );
  const result = await session.exec(["node", script, "initialize"], { timeoutMs: 30_000 });
  if (result.exitCode !== 0)
    throw new Error(`Live fixture initialization failed (exit ${result.exitCode})`);
  scripts.set(session, script);
}

/**
 * Replace only this helper's repository, snapshot and scanner exports. Fixed and
 * clean controls have secret-free history; warnings retain valid vulnerable input
 * beside malformed code, a second lockfile and Kubernetes YAML.
 */
export async function selectLiveFixture(
  session: SandboxSession,
  variant: LiveFixtureVariant,
): Promise<Snapshot> {
  const script = scripts.get(session);
  if (!script) throw new Error("Call createLiveFixtures before selecting a live fixture");
  const result = await session.exec(["node", script, variant], { timeoutMs: 30_000 });
  if (result.exitCode !== 0)
    throw new Error(`Live fixture selection failed for ${variant} (exit ${result.exitCode})`);
  return validateAcquisition(await readScannerJson(session, snapshotExport)).snapshot;
}

// Kept in /run so replacing a fixture cannot remove the executing script. All
// synthetic secret bytes are generated inside the guest and remain there.
const guestFixtureScript = String.raw`
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { inventory } from '/usr/local/bin/vibeshield-acquire';
import { gitEnvironment, writeExport } from '/usr/local/bin/export-results.mjs';

const owner = process.argv[1] + '.owner';
const owned = ['/work/repository', '/work/snapshot', '/work/.vibeshield'];
const upstream = '/work/upstream-tests';
const variants = ['vulnerable', 'fixed', 'clean', 'warnings'];
const exists = path => {
  try { return lstatSync(path); }
  catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
};
function directory(path) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || realpathSync(path) !== path)
    throw new Error('Unsafe live fixture directory');
}
function write(path, text) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, text, { flag: 'wx', mode: 0o600 });
}
function git(...args) {
  const result = spawnSync('git', [
    '-C', '/work/repository', '-c', 'user.name=VibeShield Fixture',
    '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', ...args,
  ], { env: gitEnvironment(), stdio: 'ignore', timeout: 10_000 });
  if (result.error || result.signal || result.status !== 0) throw new Error('Fixture Git failed');
}
function prepareUpstream() {
  const root = '/opt/vibeshield/rules';
  const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
  if (manifest.rules.length !== 6) throw new Error('Expected six selected rule controls');
  mkdirSync(upstream, { mode: 0o700 });
  for (const artifact of [...manifest.rules, ...manifest.artifacts]) {
    if (!/^(opengrep|fixtures)\/[a-z]+\/rule-[a-z_]+\.(yml|js|ts)$/.test(artifact.path)) continue;
    const path = join(root, artifact.path);
    if (!lstatSync(path).isFile() || realpathSync(path) !== path) throw new Error('Invalid rule fixture');
    const bytes = readFileSync(path);
    if (createHash('sha256').update(bytes).digest('hex') !== artifact.sha256)
      throw new Error('Rule fixture checksum mismatch');
    write(join(upstream, artifact.path.replace(/^(opengrep|fixtures)\//, '')), bytes);
  }
}
function select(variant) {
  if (!variants.includes(variant) || readFileSync(owner, 'utf8') !== process.argv[1])
    throw new Error('Unknown or unowned live fixture');
  directory('/work');
  for (const path of owned) {
    if (exists(path)) {
      directory(path);
      rmSync(path, { recursive: true });
    }
  }
  for (const path of ['/work/.vibeshield', '/work/.vibeshield/exports', '/work/.vibeshield/tmp', '/work/repository'])
    mkdirSync(path, { mode: 0o700 });
  git('init', '-q', '-b', 'main', '--template=');
  const vulnerable = variant === 'vulnerable' || variant === 'warnings';
  const control = vulnerable ? 'vulnerable' : 'fixed';
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const token = () => [...randomBytes(36)].map(value => alphabet[value % alphabet.length]).join('');
  write('/work/repository/README.md', 'Synthetic static scanner input. Never execute this repository.\n');
  if (vulnerable) write('/work/repository/historical.env', 'API_KEY=' + token() + '\n');
  git('add', '--all');
  git('commit', '-qm', 'Synthetic initial history');
  if (vulnerable) {
    unlinkSync('/work/repository/historical.env');
    write('/work/repository/current.env', 'API_KEY=' + token() + '\n');
  }
  write('/work/repository/app.ts', fixtures['code/' + (variant === 'clean' ? 'clean' : control) + '.ts']);
  write('/work/repository/package.json', JSON.stringify({
    name: 'vibeshield-dependency-fixture', private: true,
    scripts: { preinstall: 'touch /work/TARGET_EXECUTED' },
    devDependencies: { lodash: '^4.17.0' },
  }));
  write('/work/repository/package-lock.json', fixtures['dependencies/' + control + '/package-lock.json']);
  write('/work/repository/deployment.yaml', fixtures['config/' + control + '.yaml']);
  write('/work/repository/.github/workflows/ci.yml', fixtures['workflows/' + control + '.yml']);
  if (variant === 'warnings') {
    write('/work/repository/broken/package.json', JSON.stringify({ name: 'broken', private: true, devDependencies: { lodash: '^4.17.0' } }));
    write('/work/repository/broken/package-lock.json', '{');
    write('/work/repository/broken/pod.yaml', 'apiVersion: v1\nkind: Pod\nmetadata: {name: parser-control}\nspec: {}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: broken}\nspec: [invalid\n');
    write('/work/repository/broken/app.ts', fixtures['code/vulnerable.ts'] + '\nconst malformed = ;\n');
  }
  git('add', '--all');
  git('commit', '-qm', 'Synthetic current ' + variant + ' input');
  writeExport('/work/.vibeshield/exports/snapshot.json', inventory(
    '/work/repository', '/work/snapshot', 'https://github.com/fixture/live-' + variant,
  ));
}
try {
  if (process.argv[2] === 'initialize') {
    directory('/work');
    if ([...owned, upstream, owner].some(exists)) throw new Error('Fixture paths already exist');
    write(owner, process.argv[1]);
    prepareUpstream();
    select('vulnerable');
  } else select(process.argv[2]);
} catch {
  process.stderr.write('Live fixture preparation failed\n');
  process.exitCode = 1;
}
`;
