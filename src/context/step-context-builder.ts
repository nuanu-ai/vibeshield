import type {
  BaselineSummaryArtifact,
  InventoryArtifact,
  PiContextPackArtifact,
} from "../artifacts/contracts.js";
import type { ArtifactStore } from "../artifacts/store.js";
import { ScanStageError } from "../run/errors.js";

const contextBudget = {
  max_env_entries: 15,
  max_fact_gaps: 10,
  max_important_files: 20,
  max_observed_surfaces: 12,
} as const;

export interface BuildPiContextPackInput {
  baseline: BaselineSummaryArtifact;
  inventory: InventoryArtifact;
  store: ArtifactStore;
}

export interface BuildPiContextPackResult {
  contextPack: PiContextPackArtifact;
  contextPath: string;
}

export async function buildPiContextPack(
  input: BuildPiContextPackInput,
): Promise<BuildPiContextPackResult> {
  validateInventory(input.inventory);
  validateBaseline(input.baseline);

  const githubActionsWorkflows = input.inventory.files
    .map((file) => file.path)
    .filter((file) => file.startsWith(".github/workflows/"))
    .sort((left, right) => left.localeCompare(right));
  const iacCandidates = input.baseline.summary.iac_candidates.slice(0, 20);
  const envAndConfigCandidates = input.inventory.files
    .map((file) => file.path)
    .filter(isEnvOrConfigCandidate)
    .sort((left, right) => left.localeCompare(right))
    .slice(0, contextBudget.max_env_entries);

  const contextPack: PiContextPackArtifact = {
    budget: contextBudget,
    inventory: {
      candidate_entrypoints: candidateEntrypoints(input.inventory).slice(0, 30),
      env_and_config_candidates: envAndConfigCandidates,
      github_actions_workflows: githubActionsWorkflows,
      iac_candidates: iacCandidates,
      manifest_files: input.inventory.summary.manifest_files.slice(0, 40),
      summary: input.inventory.summary,
    },
    output_schema: {
      kind: "project-understanding.v1",
      required_sections: [
        "repo",
        "summary",
        "stack",
        "map.entrypoints",
        "map.important_files",
        "map.observed_surfaces",
        "env_and_config_surface",
        "coverage",
        "fact_gaps",
      ],
    },
    repo: {
      commit_sha: input.inventory.source.commit_sha,
      url: input.inventory.source.url,
    },
  };

  const contextPath = await input.store.writeJson({
    data: contextPack,
    id: "pi-context-pack",
    kind: "pi-context-pack.v1",
    relativePath: "outputs/pi-context-pack.v1.json",
    version: 1,
  });

  return {
    contextPack,
    contextPath,
  };
}

function validateInventory(inventory: InventoryArtifact): void {
  if (inventory.kind !== "inventory.v1" || inventory.artifact_version !== 1) {
    throw new ScanStageError({
      message: "Invalid inventory artifact schema/version.",
      stage: "context",
      userMessage: "VibeShield could not build Pi context because inventory.v1 is invalid.",
    });
  }
}

function validateBaseline(baseline: BaselineSummaryArtifact): void {
  if (baseline.kind !== "baseline-summary.v1" || baseline.artifact_version !== 1) {
    throw new ScanStageError({
      message: "Invalid baseline-summary artifact schema/version.",
      stage: "context",
      userMessage: "VibeShield could not build Pi context because baseline-summary.v1 is invalid.",
    });
  }
}

function candidateEntrypoints(inventory: InventoryArtifact): string[] {
  const candidates = inventory.files
    .map((file) => file.path)
    .filter((file) => {
      const basename = file.split("/").at(-1) ?? file;
      return (
        /(^|\/)(src|app|pages|routes|api|server)\//.test(file) ||
        ["index.ts", "index.js", "server.ts", "server.js", "app.ts", "app.js", "main.ts"].includes(
          basename,
        )
      );
    });

  return candidates.length > 0
    ? candidates.sort((left, right) => left.localeCompare(right))
    : inventory.summary.manifest_files.slice(0, 5);
}

function isEnvOrConfigCandidate(filePath: string): boolean {
  const basename = filePath.split("/").at(-1)?.toLowerCase() ?? filePath.toLowerCase();
  return (
    basename.startsWith(".env") ||
    basename.includes("secret") ||
    basename.includes("credential") ||
    basename === "vercel.json" ||
    basename === "netlify.toml" ||
    basename === "wrangler.toml"
  );
}
