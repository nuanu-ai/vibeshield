import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// Include filenames, executable modes and bytes of every build-context file.
// No tag alias or timestamp participates in this reproducible identity.
export function contentIdentity(root) {
  const hash = createHash("sha256");
  for (const relative of readdirSync(root, { recursive: true }).sort()) {
    const path = join(root, relative);
    const stat = lstatSync(path);
    if (stat.isDirectory()) continue;
    if (!stat.isFile()) throw new Error("Toolchain build inputs must be regular files");
    hash
      .update(relative)
      .update("\0")
      .update(String(stat.mode & 0o111))
      .update("\0")
      .update(createHash("sha256").update(readFileSync(path)).digest("hex"))
      .update("\n");
  }
  return `vibeshield-toolchain:sha256-${hash.digest("hex")}`;
}
