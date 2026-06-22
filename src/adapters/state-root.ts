/**
 * Resolve the state root: where state.sqlite, blobs/, and runs/ live.
 *
 * Default is ~/.vibeshield. Tests override via VIBESHIELD_STATE_ROOT or by
 * passing an explicit path. Kept out of the domain and the store classes so
 * neither knows about HOME or env.
 */

import { mkdir } from "node:fs/promises";
import path from "node:path";

export function defaultStateRoot(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE;
  if (home === undefined) {
    throw new Error("Could not determine HOME for the default state root.");
  }
  return path.join(home, ".vibeshield");
}

export function resolveStateRoot(override?: string): string {
  const root = override ?? process.env.VIBESHIELD_STATE_ROOT ?? defaultStateRoot();
  return root;
}

export async function ensureStateRoot(root: string): Promise<void> {
  await mkdir(path.join(root, "blobs"), { recursive: true });
  await mkdir(path.join(root, "runs"), { recursive: true });
}

export function stateDbPath(root: string): string {
  return path.join(root, "state.sqlite");
}
