import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdirSync, readFileSync, readlinkSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

// Test support only. The default acceptance path never installs or repairs an image.
export function prepareOpengrepWork(root = "/") {
  for (const path of [
    "/work/.vibeshield/exports",
    "/work/.vibeshield/tmp",
    "/work/snapshot",
    "/work/upstream-tests",
  ]) {
    mkdirSync(join(root, path), { recursive: true, mode: 0o700 });
  }
  const rules = join(root, "/opt/vibeshield/rules");
  const manifest = JSON.parse(readFileSync(join(rules, "manifest.json"), "utf8"));
  for (const artifact of [...manifest.rules, ...manifest.artifacts].filter((x) =>
    /\.(yml|js|ts)$/.test(x.path),
  )) {
    const dest = join(
      root,
      "/work/upstream-tests",
      artifact.path.replace(/^(opengrep|fixtures)\//, ""),
    );
    mkdirSync(dirname(dest), { recursive: true });
    copyFileSync(join(rules, artifact.path), dest);
  }
}
export function verifyOpengrepImage(expected, root = "/", allowDevelopmentCacheLink = false) {
  for (const artifact of expected) {
    try {
      if (
        createHash("sha256")
          .update(readFileSync(join(root, artifact.path)))
          .digest("hex") !== artifact.sha256
      )
        throw new Error();
    } catch {
      throw new Error(`Missing or different installed image artifact: ${artifact.path}`);
    }
  }
  if (
    readlinkSync(join(root, "/usr/local/bin/vibeshield-export-results")) !==
    "/usr/local/bin/export-results.mjs"
  )
    throw new Error("Invalid image export link");
  try {
    const cache = join(root, "/opt/vibeshield/opengrep-home/.cache/opengrep");
    if (!allowDevelopmentCacheLink && !lstatSync(cache).isDirectory()) throw new Error();
    for (const path of ["opengrep.bin", "semgrep/bin/opengrep-core"]) {
      const file = statSync(join(cache, "v1.25.0", path));
      if (!file.isFile() || file.size === 0 || (file.mode & 0o111) === 0) throw new Error();
    }
  } catch {
    throw new Error("Missing or invalid image prewarmed cache");
  }
}
