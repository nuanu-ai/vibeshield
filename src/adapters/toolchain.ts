import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Provenance, ScannerId } from "../scan/contracts.js";

const identityPath = new URL("../../toolchain/identity.mjs", import.meta.url).href;
const { contentIdentity } = (await import(identityPath)) as {
  contentIdentity(root: string): string;
};
export const toolchainRoot = fileURLToPath(new URL("../../toolchain/", import.meta.url));

export function toolchainImage(): string {
  const image = contentIdentity(toolchainRoot);
  if (process.env.VIBESHIELD_TOOLCHAIN_TAG && process.env.VIBESHIELD_TOOLCHAIN_TAG !== image)
    throw new Error(
      "VIBESHIELD_TOOLCHAIN_TAG differs from the current content-derived toolchain image",
    );
  return image;
}

export function toolchainProvenance(): Provenance {
  const manifest = JSON.parse(readFileSync(`${toolchainRoot}/versions.json`, "utf8")) as {
    engines: Record<ScannerId, { version: string }>;
  };
  const rules = JSON.parse(readFileSync(`${toolchainRoot}/rules/manifest.json`, "utf8")) as {
    revision: string;
  };
  const trivy = JSON.parse(readFileSync(`${toolchainRoot}/trivy-manifest.json`, "utf8")) as {
    bundle: { reviewedAt: string; revision: string };
  };
  return {
    image: toolchainImage(),
    tools: Object.fromEntries(
      (["gitleaks", "opengrep", "osv", "trivy", "zizmor"] as const).map((id) => [
        id,
        manifest.engines[id].version,
      ]),
    ) as Record<ScannerId, string>,
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
