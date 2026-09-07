import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { opengrepRules } from "../src/scan/policy.js";

const UPSTREAM = "https://gitlab.com/gitlab-org/security-products/sast-rules";
const REVISION = "7051ea7602a210dfb0793916afedc9a0555addb7";
const GPL_URL = "https://www.gnu.org/licenses/gpl-3.0.txt";
const GPL_SHA256 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986";
interface Artifact {
  path: string;
  upstreamPath: string;
  sha256: string;
}
export interface RuleManifest {
  upstream: string;
  revision: string;
  license: string;
  rules: (Artifact & {
    id: string;
    remediationKey: string;
    mode: "search" | "taint";
    license: string;
  })[];
  artifacts: Artifact[];
}
function hash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
function git(checkout: string, ...args: string[]): Buffer {
  return execFileSync("git", ["-C", checkout, ...args], {
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  });
}
function checkIdentity(bytes: Uint8Array, rule: (typeof opengrepRules)[number]): void {
  const text = Buffer.from(bytes).toString("utf8");
  const ids = [...text.matchAll(/^- id: ["']?([^"'\r\n]+)["']?$/gm)].map((x) => x[1]);
  const mode = text.match(/^ {2}mode: ["']?(taint|search)["']?\s*$/m)?.[1] ?? "search";
  if (
    ids.length !== 1 ||
    ids[0] !== rule.id ||
    mode !== rule.mode ||
    !text.includes("# License: GNU Lesser General Public License v3.0")
  )
    throw new Error("Rule identity or license mismatch");
}
export async function prepareRules(checkout: string, destination: string): Promise<void> {
  if (git(checkout, "rev-parse", "HEAD").toString().trim() !== REVISION)
    throw new Error("Expected frozen upstream revision");
  const manifest: RuleManifest = {
    upstream: UPSTREAM,
    revision: REVISION,
    license: "LGPL-3.0 (selected rules); MIT (upstream root)",
    rules: [],
    artifacts: [],
  };
  async function save(path: string, upstreamPath: string, bytes: Uint8Array): Promise<Artifact> {
    await mkdir(dirname(join(destination, path)), { recursive: true });
    await writeFile(join(destination, path), bytes);
    return { path, upstreamPath, sha256: hash(bytes) };
  }
  for (const rule of opengrepRules) {
    const upstreamPath = `rules/lgpl/javascript/${rule.source}.yml`;
    const bytes = git(checkout, "show", `${REVISION}:${upstreamPath}`);
    checkIdentity(bytes, rule);
    const artifact = await save(`opengrep/${rule.source}.yml`, upstreamPath, bytes);
    manifest.rules.push({
      ...artifact,
      id: rule.id,
      remediationKey: rule.remediationKey,
      mode: rule.mode,
      license: "LGPL-3.0",
    });
    for (const extension of rule.source.startsWith("eval/") ? ["js", "ts"] : ["js"]) {
      const source = `rules/lgpl/javascript/${rule.source}.${extension}`;
      manifest.artifacts.push(
        await save(
          `fixtures/${rule.source}.${extension}`,
          source,
          git(checkout, "show", `${REVISION}:${source}`),
        ),
      );
    }
  }
  for (const [source, target] of [
    ["LICENSE", "LICENSE-MIT"],
    ["rules/lgpl/LICENSE", "LICENSE-LGPL-3.0"],
  ] as const) {
    manifest.artifacts.push(
      await save(target, source, git(checkout, "show", `${REVISION}:${source}`)),
    );
  }
  const gpl = await readFile(join(checkout, "gpl-3.0.txt"));
  if (hash(gpl) !== GPL_SHA256) throw new Error("GPL license hash mismatch");
  manifest.artifacts.push(await save("LICENSE-GPL-3.0", GPL_URL, gpl));
  await writeFile(join(destination, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  await verifyRules(destination);
}
export async function verifyRules(directory: string): Promise<void> {
  const manifest: RuleManifest = JSON.parse(
    await readFile(join(directory, "manifest.json"), "utf8"),
  );
  if (manifest.upstream !== UPSTREAM || manifest.revision !== REVISION)
    throw new Error("Rule provenance revision mismatch");
  if (manifest.rules.length !== opengrepRules.length || manifest.artifacts.length !== 10)
    throw new Error("Rule manifest integrity mismatch");
  for (const selected of opengrepRules) {
    const entries = manifest.rules.filter((rule) => rule.id === selected.id);
    const entry = entries[0];
    if (
      entries.length !== 1 ||
      !entry ||
      entry.path !== `opengrep/${selected.source}.yml` ||
      entry.upstreamPath !== `rules/lgpl/javascript/${selected.source}.yml` ||
      entry.remediationKey !== selected.remediationKey ||
      entry.mode !== selected.mode ||
      entry.license !== "LGPL-3.0"
    )
      throw new Error("Rule identity mismatch");
    checkIdentity(await readFile(join(directory, entry.path)), selected);
  }
  const paths = new Set<string>();
  for (const artifact of [...manifest.rules, ...manifest.artifacts]) {
    if (
      !/^[a-zA-Z0-9_./-]+$/.test(artifact.path) ||
      artifact.path.split("/").some((x) => !x || x === ".." || x === ".") ||
      artifact.path.includes("lgpl-cc") ||
      paths.has(artifact.path)
    )
      throw new Error("Rule artifact path mismatch");
    paths.add(artifact.path);
    const file = join(directory, artifact.path);
    if (!(await lstat(file)).isFile() || hash(await readFile(file)) !== artifact.sha256)
      throw new Error("Rule artifact hash mismatch");
  }
  const actual = (await readdir(join(directory, "opengrep"), { recursive: true }))
    .filter((x) => /\.ya?ml$/.test(x))
    .map((x) => `opengrep/${x}`);
  if (actual.length !== manifest.rules.length || actual.some((x) => !paths.has(x)))
    throw new Error("Unselected rule file");
  for (const required of ["LICENSE-MIT", "LICENSE-LGPL-3.0", "LICENSE-GPL-3.0"])
    if (!paths.has(required)) throw new Error("Rule license missing");
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "--verify") await verifyRules(process.argv[3] ?? "toolchain/rules");
  else if (process.argv[2])
    await prepareRules(process.argv[2], process.argv[3] ?? "toolchain/rules");
  else
    throw new Error(
      "Usage: tsx scripts/prepare-rules.ts <exact-revision-checkout> [destination] | --verify [directory]",
    );
}
