import { readFile } from "node:fs/promises";
import path from "node:path";
import type {
  BaselineSummaryArtifact,
  BaselineToolName,
  BaselineToolSummary,
  InventoryArtifact,
  ToolAvailabilityArtifact,
} from "../artifacts/contracts.js";
import type { ArtifactStore } from "../artifacts/store.js";
import { errorMessage } from "../run/errors.js";
import { relativeArtifactPath } from "../run/file-io.js";
import type { RunJobState } from "../run/types.js";
import type { RuntimeJobResult, SandboxSession } from "../sandbox/types.js";
import { normalizeBaselineObservations } from "./observations.js";

const baselineToolOrder: BaselineToolName[] = [
  "syft",
  "trivy",
  "gitleaks",
  "actionlint",
  "zizmor",
  "checkov",
];

const baselineCheckDescriptions: Record<
  BaselineToolName,
  {
    failed: string;
    noun: string;
    running: string;
    skipped: string;
    unavailable: string;
  }
> = {
  actionlint: {
    failed: "GitHub Actions syntax check failed.",
    noun: "GitHub Actions syntax check",
    running: "Checking GitHub Actions workflow syntax.",
    skipped: "GitHub Actions syntax check skipped.",
    unavailable: "GitHub Actions syntax checker is not available.",
  },
  checkov: {
    failed: "Infrastructure configuration check failed.",
    noun: "infrastructure configuration check",
    running: "Checking infrastructure configuration.",
    skipped: "Infrastructure configuration check skipped.",
    unavailable: "Infrastructure configuration checker is not available.",
  },
  gitleaks: {
    failed: "Secret exposure check failed.",
    noun: "secret exposure check",
    running: "Checking for exposed secrets.",
    skipped: "Secret exposure check skipped.",
    unavailable: "Secret exposure checker is not available.",
  },
  syft: {
    failed: "Dependency inventory collection failed.",
    noun: "dependency inventory collection",
    running: "Collecting dependency inventory.",
    skipped: "Dependency inventory collection skipped.",
    unavailable: "Dependency inventory collector is not available.",
  },
  trivy: {
    failed: "Dependency vulnerability check failed.",
    noun: "dependency vulnerability check",
    running: "Checking dependency vulnerabilities.",
    skipped: "Dependency vulnerability check skipped.",
    unavailable: "Dependency vulnerability checker is not available.",
  },
  zizmor: {
    failed: "GitHub Actions security check failed.",
    noun: "GitHub Actions security check",
    running: "Checking GitHub Actions security signals.",
    skipped: "GitHub Actions security check skipped.",
    unavailable: "GitHub Actions security checker is not available.",
  },
};

export interface BaselineProgressEvent {
  job?: string;
  message: string;
  type: string;
}

export interface RunDeterministicBaselineInput {
  commitSha: string | null;
  generatedAt: string;
  inventory: InventoryArtifact;
  onProgress?: (event: BaselineProgressEvent) => Promise<void>;
  outputsDir: string;
  runDir: string;
  sandbox: SandboxSession;
  sourceUrl: string;
  store: ArtifactStore;
}

export interface RunDeterministicBaselineResult {
  jobStates: RunJobState[];
  summary: BaselineSummaryArtifact;
  summaryPath: string;
}

export async function runDeterministicBaseline(
  input: RunDeterministicBaselineInput,
): Promise<RunDeterministicBaselineResult> {
  const githubActionsWorkflows = input.inventory.files
    .map((file) => file.path)
    .filter(isGithubActionsWorkflow)
    .sort((left, right) => left.localeCompare(right));
  const iacCandidates = input.inventory.files
    .map((file) => file.path)
    .filter(isIacCandidatePath)
    .sort((left, right) => left.localeCompare(right));

  const toolSummaries: BaselineToolSummary[] = [];
  const jobStates: RunJobState[] = [];
  let sbomSandboxPath: string | undefined;

  const toolRequests = baselineToolOrder.map((tool) => {
    const skippedReason = skipReasonForTool(tool, githubActionsWorkflows, iacCandidates);
    return {
      required: isToolRequired(tool, githubActionsWorkflows, iacCandidates),
      ...(skippedReason === undefined ? {} : { skippedReason }),
      tool,
    };
  });

  const availabilityResult = await input.sandbox
    .prepareBaselineTools({
      generatedAt: input.generatedAt,
      tools: toolRequests,
    })
    .catch(async (error: unknown) => {
      const diagnostic = `Could not prepare baseline checks inside Daytona sandbox: ${errorMessage(
        error,
      )}`;
      await input.onProgress?.({
        message: diagnostic,
        type: "baseline.tools.prepare_failed",
      });

      const availability = buildFailedToolAvailability({
        diagnostic,
        generatedAt: input.generatedAt,
        tools: toolRequests,
      });
      const artifactPath = await input.store.writeJson({
        data: availability,
        id: "baseline-tool-availability",
        kind: "tool-availability",
        relativePath: "outputs/baseline/tool-availability.json",
      });

      return {
        artifactPath,
        availability,
      };
    });

  const toolAvailabilityPath =
    "artifactPath" in availabilityResult
      ? availabilityResult.artifactPath
      : await pullRuntimeArtifact({
          artifact: availabilityResult.artifact,
          job: "tool-availability",
          outputsDir: input.outputsDir,
          runDir: input.runDir,
          sandbox: input.sandbox,
          stage: "deterministic-baseline",
        });
  if (!("artifactPath" in availabilityResult)) {
    input.store.register({
      id: "baseline-tool-availability",
      kind: "tool-availability",
      path: toolAvailabilityPath,
    });
  }

  const availabilityByTool = new Map(
    availabilityResult.availability.tools.map((tool) => [tool.tool, tool]),
  );

  for (const tool of baselineToolOrder) {
    const availability = availabilityByTool.get(tool);
    if (availability?.required !== false) {
      await input.onProgress?.({
        job: tool,
        message: baselineCheckDescriptions[tool].running,
        type: "baseline.job.started",
      });
    }

    const result =
      availability?.required === true && availability.status !== "available"
        ? buildUnavailableToolResult({
            diagnostics: [baselineCheckDescriptions[tool].unavailable],
            generatedAt: input.generatedAt,
            tool,
          })
        : await input.sandbox
            .runJob({
              baseline: {
                hasGithubActions: githubActionsWorkflows.length > 0,
                hasIacCandidates: iacCandidates.length > 0,
                ...(sbomSandboxPath === undefined ? {} : { sbomSandboxPath }),
                tool,
              },
              generatedAt: input.generatedAt,
              kind: "baseline-tool",
              name: tool,
              stage: "deterministic-baseline",
            })
            .catch((error: unknown) =>
              buildFailedToolResult({
                diagnostics: [
                  `Could not complete ${baselineCheckDescriptions[tool].noun}: ${errorMessage(
                    error,
                  )}`,
                ],
                generatedAt: input.generatedAt,
                tool,
              }),
            );

    const artifactPaths = await pullRuntimeArtifacts({
      job: tool,
      outputsDir: input.outputsDir,
      result,
      runDir: input.runDir,
      sandbox: input.sandbox,
    });
    const observations = await readNormalizedObservations({
      artifactPaths,
      fallback: result.observations,
      resultStatus: result.status,
      runDir: input.runDir,
      tool,
    });

    if (tool === "syft") {
      sbomSandboxPath = result.artifacts.find((artifact) =>
        artifact.relativePath.endsWith("syft-sbom.json"),
      )?.sandboxPath;
    }

    const toolSummary: BaselineToolSummary = {
      artifacts: artifactPaths,
      diagnostics: result.diagnostics,
      invocation: result.invocation,
      observations,
      ...(result.exitCode === undefined ? {} : { exit_code: result.exitCode }),
      ...(result.skippedReason === undefined ? {} : { skipped_reason: result.skippedReason }),
      status: result.status,
      tool,
      ...(result.version === undefined ? {} : { version: result.version }),
    };
    toolSummaries.push(toolSummary);

    jobStates.push({
      artifacts: artifactPaths,
      diagnostics: result.diagnostics,
      finished_at: result.finishedAt,
      invocation: result.invocation,
      name: tool,
      observations: observations.length,
      ...(result.skippedReason === undefined ? {} : { skipped_reason: result.skippedReason }),
      started_at: result.startedAt,
      status: result.status === "completed" ? "success" : result.status,
      ...(result.version === undefined ? {} : { version: result.version }),
    });

    if (result.status === "skipped" || result.status === "failed") {
      const statusMessage =
        result.status === "skipped"
          ? skippedBaselineMessage(tool, result.skippedReason)
          : baselineCheckDescriptions[tool].failed;
      await input.onProgress?.({
        job: tool,
        message: statusMessage,
        type: result.status === "skipped" ? "baseline.job.skipped" : "baseline.job.failed",
      });
    }
  }

  const sbomArtifact = sbomArtifactPath(toolSummaries);
  const summary: BaselineSummaryArtifact = {
    generated_at: input.generatedAt,
    kind: "baseline-summary",
    source: {
      commit_sha: input.commitSha,
      url: input.sourceUrl,
    },
    summary: {
      github_actions_workflows: githubActionsWorkflows,
      iac_candidates: iacCandidates,
      important_paths: buildImportantPaths(input.inventory, githubActionsWorkflows, iacCandidates),
      observation_counts: countObservations(toolSummaries),
      ...(sbomArtifact === undefined ? {} : { sbom_artifact: sbomArtifact }),
      tool_availability_artifact: toolAvailabilityPath,
      tool_order: baselineToolOrder,
    },
    tools: toolSummaries,
  };

  const summaryPath = await input.store.writeJson({
    data: summary,
    id: "baseline-summary",
    kind: "baseline-summary",
    relativePath: "outputs/baseline-summary.json",
  });

  return {
    jobStates,
    summary,
    summaryPath,
  };
}

function skippedBaselineMessage(tool: BaselineToolName, reason: string | undefined): string {
  return reason === undefined
    ? baselineCheckDescriptions[tool].skipped
    : `${baselineCheckDescriptions[tool].skipped} ${reason}`;
}

function buildFailedToolAvailability(input: {
  diagnostic: string;
  generatedAt: string;
  tools: Array<{
    required: boolean;
    skippedReason?: string;
    tool: BaselineToolName;
  }>;
}): ToolAvailabilityArtifact {
  return {
    generated_at: input.generatedAt,
    kind: "tool-availability",
    tool_bin_dir: "",
    tools: input.tools.map((tool) => {
      if (!tool.required) {
        return {
          attempts: [],
          diagnostics: [],
          required: false,
          ...(tool.skippedReason === undefined ? {} : { skipped_reason: tool.skippedReason }),
          status: "not_required",
          tool: tool.tool,
        };
      }

      return {
        attempts: [],
        diagnostics: [input.diagnostic],
        required: true,
        status: "failed",
        tool: tool.tool,
      };
    }),
  };
}

function buildUnavailableToolResult(input: {
  diagnostics: string[];
  generatedAt: string;
  tool: BaselineToolName;
}): RuntimeJobResult {
  return {
    artifacts: [],
    diagnostics: input.diagnostics,
    finishedAt: new Date().toISOString(),
    invocation: {
      command: input.tool,
    },
    kind: "baseline-tool",
    observations: [],
    startedAt: input.generatedAt,
    status: "failed",
  };
}

function buildFailedToolResult(input: {
  diagnostics: string[];
  generatedAt: string;
  tool: BaselineToolName;
}): RuntimeJobResult {
  return {
    artifacts: [],
    diagnostics: input.diagnostics,
    finishedAt: new Date().toISOString(),
    invocation: {
      command: input.tool,
    },
    kind: "baseline-tool",
    observations: [],
    startedAt: input.generatedAt,
    status: "failed",
  };
}

async function readNormalizedObservations(input: {
  artifactPaths: string[];
  fallback: BaselineToolSummary["observations"];
  resultStatus: RuntimeJobResult["status"];
  runDir: string;
  tool: BaselineToolName;
}): Promise<BaselineToolSummary["observations"]> {
  const stdout = await readArtifactText(input.runDir, input.artifactPaths, "stdout.redacted.txt");
  const stderr = await readArtifactText(input.runDir, input.artifactPaths, "stderr.redacted.log");
  const observations = normalizeBaselineObservations({
    status: input.resultStatus,
    ...(stderr === undefined ? {} : { stderr }),
    ...(stdout === undefined ? {} : { stdout }),
    tool: input.tool,
  });
  return observations.length > 0 ? observations : input.fallback;
}

async function readArtifactText(
  runDir: string,
  artifactPaths: string[],
  suffix: string,
): Promise<string | undefined> {
  const relativePath = artifactPaths.find((artifactPath) => artifactPath.endsWith(suffix));
  if (relativePath === undefined) {
    return undefined;
  }

  try {
    return await readFile(path.join(runDir, relativePath), "utf8");
  } catch {
    return undefined;
  }
}

async function pullRuntimeArtifacts(input: {
  job: string;
  outputsDir: string;
  result: RuntimeJobResult;
  runDir: string;
  sandbox: SandboxSession;
}): Promise<string[]> {
  const artifactPaths: string[] = [];

  for (const artifact of input.result.artifacts) {
    artifactPaths.push(
      await pullRuntimeArtifact({
        artifact,
        job: input.job,
        outputsDir: input.outputsDir,
        runDir: input.runDir,
        sandbox: input.sandbox,
        stage: "deterministic-baseline",
      }),
    );
  }

  return artifactPaths;
}

async function pullRuntimeArtifact(input: {
  artifact: { relativePath: string; sandboxPath: string };
  job: string;
  outputsDir: string;
  runDir: string;
  sandbox: SandboxSession;
  stage: "deterministic-baseline";
}): Promise<string> {
  const localPath = path.join(input.outputsDir, input.artifact.relativePath);
  await input.sandbox.pullFile(input.artifact.sandboxPath, localPath, {
    artifact: input.artifact.relativePath,
    job: input.job,
    stage: input.stage,
  });
  return relativeArtifactPath(input.runDir, localPath);
}

function buildImportantPaths(
  inventory: InventoryArtifact,
  githubActionsWorkflows: string[],
  iacCandidates: string[],
): string[] {
  return [
    ...inventory.summary.manifest_files,
    ...githubActionsWorkflows,
    ...iacCandidates,
    ...inventory.files
      .map((file) => file.path)
      .filter((file) => /(^|\/)(src|app|pages|routes|api)\//.test(file))
      .slice(0, 20),
  ]
    .filter((value, index, values) => values.indexOf(value) === index)
    .slice(0, 40);
}

function countObservations(tools: BaselineToolSummary[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const tool of tools) {
    counts[tool.tool] = tool.observations.length;
  }
  return counts;
}

function sbomArtifactPath(tools: BaselineToolSummary[]): string | undefined {
  return tools
    .find((tool) => tool.tool === "syft")
    ?.artifacts.find((artifact) => artifact.endsWith("baseline/syft-sbom.json"));
}

function isGithubActionsWorkflow(filePath: string): boolean {
  return filePath.startsWith(".github/workflows/");
}

function isIacCandidatePath(filePath: string): boolean {
  const basename = path.posix.basename(filePath);
  return (
    filePath.endsWith(".tf") ||
    basename === "Dockerfile" ||
    basename === "docker-compose.yml" ||
    basename === "compose.yaml" ||
    basename === "compose.yml" ||
    filePath.endsWith(".k8s.yaml") ||
    filePath.endsWith(".k8s.yml") ||
    filePath.includes("terraform") ||
    filePath.includes("kubernetes")
  );
}

function isToolRequired(
  tool: BaselineToolName,
  githubActionsWorkflows: string[],
  iacCandidates: string[],
): boolean {
  if (tool === "actionlint" || tool === "zizmor") {
    return githubActionsWorkflows.length > 0;
  }
  if (tool === "checkov") {
    return iacCandidates.length > 0;
  }
  return true;
}

function skipReasonForTool(
  tool: BaselineToolName,
  githubActionsWorkflows: string[],
  iacCandidates: string[],
): string | undefined {
  if ((tool === "actionlint" || tool === "zizmor") && githubActionsWorkflows.length === 0) {
    return "No GitHub Actions workflows were detected in inventory.";
  }
  if (tool === "checkov" && iacCandidates.length === 0) {
    return "No IaC/config candidates were detected in inventory.";
  }
  return undefined;
}
