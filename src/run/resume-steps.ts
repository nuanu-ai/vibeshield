export const resumeStepDefinitions = [
  {
    description: "Rebuild repository inventory, then rerun every downstream step.",
    step: "inventory",
  },
  {
    aliases: ["baseline"],
    description: "Rerun deterministic baseline checks, context, map, and hypotheses.",
    step: "deterministic-baseline",
  },
  {
    aliases: ["pi-context", "pi-context-pack"],
    description: "Rebuild the Pi context pack, then rerun map and hypotheses.",
    step: "context",
  },
  {
    description: "Rebuild the deterministic coverage/structure map and all downstream artifacts.",
    step: "coverage-structure",
  },
  {
    aliases: ["stack"],
    description: "Rerun stack/build/dependency mapping and all downstream artifacts.",
    step: "stack-build-deps",
  },
  {
    description: "Rerun entrypoint mapping and all downstream artifacts.",
    step: "entrypoints",
  },
  {
    aliases: ["config"],
    description: "Rerun configuration/secret-reference mapping and all downstream artifacts.",
    step: "config-secrets",
  },
  {
    aliases: ["auth"],
    description: "Rerun auth/access mapping and all downstream artifacts.",
    step: "auth-access",
  },
  {
    aliases: ["storage"],
    description: "Rerun storage/data-model mapping and all downstream artifacts.",
    step: "storage-data-model",
  },
  {
    aliases: ["integrations", "egress"],
    description: "Rerun external integration/egress mapping and all downstream artifacts.",
    step: "external-integrations-egress",
  },
  {
    aliases: ["infra"],
    description: "Rerun infrastructure/deploy mapping and all downstream artifacts.",
    step: "infra-deploy",
  },
  {
    aliases: ["sinks"],
    description: "Rerun operation-sink mapping and all downstream artifacts.",
    step: "operation-sinks",
  },
  {
    description: "Rerun crypto/randomness mapping and all downstream artifacts.",
    step: "crypto",
  },
  {
    aliases: ["logging"],
    description: "Rerun logging/observability mapping and all downstream artifacts.",
    step: "logging-observability",
  },
  {
    aliases: ["flows"],
    description: "Rerun data-flow mapping and all downstream artifacts.",
    step: "data-flows",
  },
  {
    aliases: ["boundaries"],
    description: "Rerun trust-boundary synthesis, repository map, and hypotheses.",
    step: "trust-boundaries",
  },
  {
    aliases: ["repo-map"],
    description: "Rerun repository-map synthesis and hypotheses.",
    step: "repository-map",
  },
  {
    aliases: ["hypotheses"],
    description: "Rerun attack-hypothesis generation and the final report.",
    step: "attack-hypotheses",
  },
  {
    aliases: ["report"],
    description: "Rerender only the owner-facing final Markdown and PDF report.",
    step: "final-report",
  },
] as const;

export type RunResumeFromStep = (typeof resumeStepDefinitions)[number]["step"];

const resumeStepAliasMap = new Map<string, RunResumeFromStep>(
  resumeStepDefinitions.flatMap((definition) => {
    const aliases = "aliases" in definition ? definition.aliases : [];
    return [
      [definition.step, definition.step],
      ...aliases.map((alias) => [alias, definition.step] as const),
    ];
  }),
);

export function parseRunResumeFromStep(value: string): RunResumeFromStep | undefined {
  return resumeStepAliasMap.get(normalizeResumeStep(value));
}

function normalizeResumeStep(value: string): string {
  return value.trim().toLowerCase().replaceAll("_", "-");
}
