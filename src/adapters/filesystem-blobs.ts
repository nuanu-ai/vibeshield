/**
 * FilesystemBlobs — content-addressed ArtifactStore under <root>/blobs/sha256.
 *
 * Layout: blobs/sha256/<first 2 hex>/<full hash>. Identical bytes reuse one
 * blob (write is a no-op when the path exists). Raw scanner output is redacted
 * upstream; this layer just stores whatever bytes it is given.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import type { ArtifactStore, StoredBlob } from "../ports/artifact-store.js";

export class FilesystemBlobs implements ArtifactStore {
  constructor(private readonly root: string) {}

  async store(data: Uint8Array): Promise<StoredBlob> {
    const hash = sha256(data);
    const rel = blobPath(hash);
    const abs = path.join(this.root, rel);
    const existing = await statSafe(abs);
    if (existing === null) {
      await mkdir(path.dirname(abs), { recursive: true });
      await writeFile(abs, data);
    }
    return { sha256: hash, bytes: data.byteLength };
  }

  async read(sha256: string): Promise<Uint8Array> {
    const abs = path.join(this.root, blobPath(sha256));
    return readFile(abs);
  }

  async exists(sha256: string): Promise<boolean> {
    const abs = path.join(this.root, blobPath(sha256));
    return (await statSafe(abs)) !== null;
  }
}

function sha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** blobs/sha256/<first 2 hex>/<full hash> */
function blobPath(sha256: string): string {
  if (sha256.length < 2) {
    throw new Error(`invalid sha256: ${sha256}`);
  }
  return path.join("blobs", "sha256", sha256.slice(0, 2), sha256);
}

async function statSafe(p: string): Promise<number | null> {
  try {
    const s = await stat(p);
    return s.size;
  } catch {
    return null;
  }
}
