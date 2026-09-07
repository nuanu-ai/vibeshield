import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { contentIdentity } from "./identity.mjs";
import { verifyTrivyBundle } from "./trivy.mjs";

export function verifyInstalled(manifest) {
  if (manifest.base && process.version !== `v${manifest.base.version}`)
    throw new Error("Installed base Node version mismatch");
  const versions = {};
  for (const [id, tool] of Object.entries(manifest.engines)) {
    const result = spawnSync(tool.command[0], tool.command.slice(1), {
      encoding: "utf8",
      timeout: 30000,
      maxBuffer: 65536,
      env: {
        PATH: "/usr/local/bin:/usr/bin:/bin",
        HOME: "/opt/vibeshield/opengrep-home",
        LANG: "C.UTF-8",
      },
    });
    if (
      result.error ||
      result.signal ||
      result.status !== 0 ||
      result.stdout.trim().split("\n")[0] !== tool.versionLine
    )
      throw new Error(`Installed engine version mismatch: ${id}`);
    versions[id] = tool.version;
  }
  return versions;
}

export function verifyFiles(files, root) {
  for (const file of files) {
    const path = join(root, file.path);
    if (
      !/^[a-f0-9]{64}$/.test(file.sha256) ||
      realpathSync(path) !== path ||
      !lstatSync(path).isFile() ||
      createHash("sha256").update(readFileSync(path)).digest("hex") !== file.sha256
    )
      throw new Error(`Installed artifact mismatch: ${file.path}`);
  }
}

export function verifyRuleManifests(manifest, sourceRoot, installedRoot = "/opt/vibeshield") {
  verifyFiles(
    Object.values(manifest.rules).map((rule) => ({ path: rule.manifest, sha256: rule.sha256 })),
    sourceRoot,
  );
  verifyFiles(
    Object.entries(manifest.rules).map(([engine, rule]) => ({
      path: engine === "opengrep" ? "rules/manifest.json" : "trivy/manifest.json",
      sha256: rule.sha256,
    })),
    installedRoot,
  );
}

export function verifyImage(root = "/opt/vibeshield/build-input", expectedImage) {
  const image = contentIdentity(root);
  if (expectedImage !== undefined && image !== expectedImage)
    throw new Error("Installed toolchain content differs from the accepted image");
  const manifest = JSON.parse(readFileSync(join(root, "versions.json"), "utf8"));
  const tools = verifyInstalled(manifest);
  verifyFiles(
    [
      manifest.base,
      ...Object.values(manifest.engines),
      ...Object.values(manifest.supportingTools),
      manifest.rules.trivy,
    ].map((entry) => ({ path: entry.licenseFile, sha256: entry.licenseSha256 })),
    "/opt/vibeshield",
  );
  verifyRuleManifests(manifest, root);
  const packages = spawnSync(
    "dpkg-query",
    // biome-ignore lint/suspicious/noTemplateCurlyInString: dpkg-query placeholders, not JavaScript interpolation.
    ["-W", "-f=${Package}=${Version}\\n", ...Object.keys(manifest.apt.packages)],
    { encoding: "utf8", timeout: 10000 },
  );
  if (packages.status !== 0) throw new Error("Installed Debian package inventory unavailable");
  const installed = new Set(packages.stdout.trim().split("\n"));
  for (const [name, version] of Object.entries(manifest.apt.packages))
    if (!installed.has(`${name}=${version}`))
      throw new Error(`Installed Debian package version mismatch: ${name}`);
  const rules = JSON.parse(readFileSync(join(root, "rules/manifest.json"), "utf8"));
  verifyFiles([...rules.rules, ...rules.artifacts], "/opt/vibeshield/rules");
  const scripts = {
    "acquire.mjs": "/usr/local/bin/vibeshield-acquire",
    "export-results.mjs": "/usr/local/bin/export-results.mjs",
    "opengrep.mjs": "/usr/local/bin/vibeshield-opengrep",
    "osv.mjs": "/usr/local/bin/vibeshield-osv",
    "trivy.mjs": "/usr/local/bin/vibeshield-trivy",
    "zizmor.mjs": "/usr/local/bin/vibeshield-zizmor",
  };
  verifyFiles(
    Object.entries(scripts).map(([source, path]) => ({
      path,
      sha256: createHash("sha256")
        .update(readFileSync(join(root, source)))
        .digest("hex"),
    })),
    "/",
  );
  const trivy = verifyTrivyBundle();
  return {
    image,
    tools,
    rulesRevision: rules.revision,
    advisoryData: [
      {
        source: "Trivy checks",
        retrievedAt: trivy.bundle.reviewedAt,
        revision: trivy.bundle.revision,
        stale:
          Date.now() < Date.parse(trivy.bundle.reviewedAt) ||
          Date.now() - Date.parse(trivy.bundle.reviewedAt) > 30 * 86400000,
      },
    ],
  };
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(verifyImage(undefined, process.argv[2]))}\n`);
  } catch (error) {
    process.stderr.write(`Toolchain verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
