import { randomUUID } from "node:crypto";
import { appendFile, mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";

export async function ensureDirectory(dirPath: string): Promise<void> {
  await mkdir(dirPath, { recursive: true });
}

export async function writeJsonAtomic(filePath: string, data: unknown): Promise<void> {
  const tempPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  await rename(tempPath, filePath);
}

export async function appendJsonLine(filePath: string, data: unknown): Promise<void> {
  await appendFile(filePath, `${JSON.stringify(data)}\n`, "utf8");
}

export function relativeArtifactPath(runDir: string, artifactPath: string): string {
  return path.relative(runDir, artifactPath).split(path.sep).join("/");
}
