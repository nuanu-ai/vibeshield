import { readFile } from "node:fs/promises";
import path from "node:path";
import { ensureDirectory, relativeArtifactPath, writeJsonAtomic } from "../run/file-io.js";
import { redactDeep } from "../run/redaction.js";
import type { ArtifactKind } from "./contracts.js";

export interface ArtifactRecord {
  kind: ArtifactKind | "diagnostic-log";
  path: string;
}

export class ArtifactStore {
  private readonly records = new Map<string, ArtifactRecord>();

  constructor(
    readonly runDir: string,
    readonly outputsDir: string,
  ) {}

  async writeJson<T>(input: {
    data: T;
    id: string;
    kind: ArtifactKind;
    relativePath: string;
  }): Promise<string> {
    const absolutePath = path.join(this.runDir, input.relativePath);
    await ensureDirectory(path.dirname(absolutePath));
    await writeJsonAtomic(absolutePath, redactDeep(input.data));
    const relativePath = relativeArtifactPath(this.runDir, absolutePath);
    this.records.set(input.id, {
      kind: input.kind,
      path: relativePath,
    });
    return relativePath;
  }

  async readJson<T>(id: string): Promise<T> {
    const record = this.require(id);
    const absolutePath = path.join(this.runDir, record.path);
    return JSON.parse(await readFile(absolutePath, "utf8")) as T;
  }

  register(input: ArtifactRecord & { id: string }): void {
    this.records.set(input.id, {
      kind: input.kind,
      path: input.path,
    });
  }

  get(id: string): ArtifactRecord | undefined {
    return this.records.get(id);
  }

  require(id: string): ArtifactRecord {
    const record = this.records.get(id);
    if (record === undefined) {
      throw new Error(`Missing required artifact: ${id}`);
    }
    return record;
  }

  list(): ArtifactRecord[] {
    return [...this.records.values()];
  }
}
