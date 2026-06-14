export const resumeStepDefinitions = [
  {
    description: "Repository inventory",
    step: "inventory",
  },
  {
    aliases: ["baseline"],
    description: "Quick security scanners",
    step: "deterministic-baseline",
  },
  {
    aliases: ["pi-context", "pi-context-pack"],
    description: "AI analysis context pack",
    step: "context",
  },
  {
    description: "Coverage and structure",
    step: "coverage-structure",
  },
  {
    aliases: ["stack"],
    description: "Stack, build, dependencies",
    step: "stack-build-deps",
  },
  {
    description: "Entry points and routes",
    step: "entrypoints",
  },
  {
    aliases: ["config"],
    description: "Config and secret references",
    step: "config-secrets",
  },
  {
    aliases: ["auth"],
    description: "Auth and access control",
    step: "auth-access",
  },
  {
    aliases: ["storage"],
    description: "Storage and data model",
    step: "storage-data-model",
  },
  {
    aliases: ["integrations", "egress"],
    description: "Integrations and egress",
    step: "external-integrations-egress",
  },
  {
    aliases: ["infra"],
    description: "Infrastructure and deploy",
    step: "infra-deploy",
  },
  {
    aliases: ["sinks"],
    description: "Operation sinks",
    step: "operation-sinks",
  },
  {
    description: "Crypto and randomness",
    step: "crypto",
  },
  {
    aliases: ["logging"],
    description: "Logging and observability",
    step: "logging-observability",
  },
  {
    aliases: ["flows"],
    description: "Input-to-sink data flows",
    step: "data-flows",
  },
  {
    aliases: ["boundaries"],
    description: "Trust boundaries",
    step: "trust-boundaries",
  },
  {
    aliases: ["repo-map"],
    description: "Repository-map synthesis",
    step: "repository-map",
  },
  {
    aliases: ["hypotheses"],
    description: "Prioritized attack hypotheses",
    step: "attack-hypotheses",
  },
  {
    aliases: ["report"],
    description: "Markdown + PDF report",
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
