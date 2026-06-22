import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FilesystemBlobs } from "../src/adapters/filesystem-blobs.js";

describe("FilesystemBlobs", () => {
  let root: string;
  let store: FilesystemBlobs;

  beforeEach(async () => {
    root = await mkdtemp(path.join(tmpdir(), "vsblobs-"));
    store = new FilesystemBlobs(root);
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("stores bytes and reads them back identically", async () => {
    const payload = new TextEncoder().encode("gitleaks raw output");
    const { sha256, bytes } = await store.store(payload);
    expect(bytes).toBe(payload.byteLength);
    expect(sha256).toHaveLength(64);
    const back = await store.read(sha256);
    expect(new TextDecoder().decode(back)).toBe("gitleaks raw output");
  });

  it("deduplicates identical bytes to one blob", async () => {
    const payload = new TextEncoder().encode("same bytes");
    const a = await store.store(payload);
    const b = await store.store(payload);
    expect(a.sha256).toBe(b.sha256);
    expect(await store.exists(a.sha256)).toBe(true);
  });

  it("distinguishes different content", async () => {
    const a = await store.store(new TextEncoder().encode("aaa"));
    const b = await store.store(new TextEncoder().encode("bbb"));
    expect(a.sha256).not.toBe(b.sha256);
  });

  it("reports exists=false for a missing hash", async () => {
    expect(await store.exists("0".repeat(64))).toBe(false);
  });
});
