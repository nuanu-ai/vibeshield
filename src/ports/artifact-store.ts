/**
 * ArtifactStore port — content-addressed blob storage for raw artifacts.
 *
 * Production adapter is filesystem blobs under blobs/sha256/<prefix>/<hash>.
 * Identical bytes reuse one blob. Raw scanner output is redacted of secret
 * values before it lands here.
 */

export interface StoredBlob {
  readonly sha256: string;
  readonly bytes: number;
}

export interface ArtifactStore {
  /** Store bytes, dedup by sha256. Returns the hash + size. */
  store(data: Uint8Array): Promise<StoredBlob>;
  /** Read a blob by hash. Throws if missing. */
  read(sha256: string): Promise<Uint8Array>;
  /** True if the blob exists. */
  exists(sha256: string): Promise<boolean>;
}
