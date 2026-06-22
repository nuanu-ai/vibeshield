import type { RemediationAction } from "../domain/action.js";
import type { ModelEnhanceBatchInput, ModelProvider } from "../ports/model-provider.js";

export const DEFAULT_REMEDIATION_MODEL = "anthropic/claude-sonnet-4.6";

type FetchFn = typeof fetch;

export interface OpenRouterModelProviderOptions {
  readonly apiKey?: string;
  readonly model?: string;
  readonly fetchFn?: FetchFn;
}

interface OpenRouterChatResponse {
  readonly choices?: ReadonlyArray<{
    readonly message?: {
      readonly content?: string | null;
    };
  }>;
}

interface ModelRemediationResponse {
  readonly actions?: unknown;
  readonly remediations?: unknown;
}

/** OpenRouter-backed one-call remediation enhancer. */
export class OpenRouterModelProvider implements ModelProvider {
  private readonly apiKey: string | undefined;
  private readonly model: string;
  private readonly fetchFn: FetchFn;

  constructor(opts: OpenRouterModelProviderOptions = {}) {
    this.apiKey = nonEmpty(opts.apiKey);
    this.model = nonEmpty(opts.model) ?? DEFAULT_REMEDIATION_MODEL;
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  async isAvailable(): Promise<boolean> {
    return this.apiKey !== undefined;
  }

  async enhance(input: ModelEnhanceBatchInput): Promise<ReadonlyArray<RemediationAction> | null> {
    if (!(await this.isAvailable()) || input.actions.length === 0) {
      return null;
    }

    try {
      const response = await this.fetchFn("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://github.com/nuanu-ai/vibeshield",
          "X-Title": "VibeShield",
        },
        body: JSON.stringify({
          model: this.model,
          temperature: 0.2,
          max_tokens: 6000,
          response_format: { type: "json_object" },
          messages: [
            {
              role: "system",
              content: systemPrompt(),
            },
            {
              role: "user",
              content: JSON.stringify(input),
            },
          ],
        }),
      });

      if (!response.ok) {
        return null;
      }
      const body = (await response.json()) as OpenRouterChatResponse;
      const content = body.choices?.[0]?.message?.content;
      if (typeof content !== "string" || content.trim() === "") {
        return null;
      }
      const parsed = parseModelJson(content);
      const actions = Array.isArray(parsed.actions)
        ? parsed.actions
        : Array.isArray(parsed.remediations)
          ? parsed.remediations
          : undefined;
      if (actions === undefined) {
        return null;
      }
      return actions.map(parseRemediationAction);
    } catch {
      return null;
    }
  }
}

function parseModelJson(content: string): ModelRemediationResponse {
  const body = content.trim();
  try {
    return JSON.parse(body) as ModelRemediationResponse;
  } catch {
    for (const fenced of markdownFenceBodies(body)) {
      try {
        return JSON.parse(fenced) as ModelRemediationResponse;
      } catch {
        // Fenced extraction is allowed; malformed JSON still falls back.
      }
    }
    throw new Error("model response was not strict or fenced JSON");
  }
}

function markdownFenceBodies(body: string): string[] {
  const matches = body.matchAll(/```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```/gi);
  return [...matches]
    .map((match) => match[1]?.trim())
    .filter((match): match is string => match !== undefined && match !== "");
}

function systemPrompt(): string {
  return [
    "You improve VibeShield remediation copy for beginner-built web projects.",
    'Return only strict JSON: {"actions":[...]} with one item per input action.',
    "Never change candidateId, priority, severity, verdict, finding ids, file paths, or line numbers.",
    "Use only the supplied findings, redacted snippets, affected files, and catalog remediation.",
    "Do not invent reachability, production impact, exploitability, or secret values.",
    "Keep code-change steps separate from operational steps.",
    "Each action must include candidateId, title, risk, whyFixNow, fixSteps, operationalSteps, agentPrompt, verifySteps.",
  ].join("\n");
}

function parseRemediationAction(value: unknown): RemediationAction {
  if (!isRecord(value)) {
    throw new Error("model remediation action is not an object");
  }
  return {
    candidateId: requiredStringField(value, ["candidateId", "candidate_id"], "candidateId"),
    title: requiredStringField(value, ["title"], "title"),
    risk: requiredStringField(value, ["risk"], "risk"),
    whyFixNow: requiredStringField(value, ["whyFixNow", "why_fix_now", "why"], "whyFixNow"),
    fixSteps: requiredStringArrayField(value, ["fixSteps", "fix_steps", "steps"], "fixSteps"),
    operationalSteps: optionalStringArrayField(value, [
      "operationalSteps",
      "operational_steps",
      "opsSteps",
    ]),
    agentPrompt: requiredStringField(
      value,
      ["agentPrompt", "agent_prompt", "prompt"],
      "agentPrompt",
    ),
    verifySteps: requiredStringArrayField(
      value,
      ["verifySteps", "verify_steps", "verification", "verificationSteps"],
      "verifySteps",
    ),
    fromCatalog: false,
  };
}

function requiredStringField(
  value: Readonly<Record<string, unknown>>,
  names: ReadonlyArray<string>,
  field: string,
): string {
  return requiredString(firstField(value, names), field);
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`model remediation action field ${field} is missing`);
  }
  return value;
}

function requiredStringArrayField(
  value: Readonly<Record<string, unknown>>,
  names: ReadonlyArray<string>,
  field: string,
): ReadonlyArray<string> {
  return requiredStringArray(firstField(value, names), field);
}

function optionalStringArrayField(
  value: Readonly<Record<string, unknown>>,
  names: ReadonlyArray<string>,
): ReadonlyArray<string> {
  const raw = firstField(value, names);
  return raw === undefined ? [] : requiredStringArray(raw, names[0] ?? "operationalSteps");
}

function requiredStringArray(value: unknown, field: string): ReadonlyArray<string> {
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || item.trim() === "")
  ) {
    throw new Error(`model remediation action field ${field} is invalid`);
  }
  return value;
}

function firstField(
  value: Readonly<Record<string, unknown>>,
  names: ReadonlyArray<string>,
): unknown {
  for (const name of names) {
    if (value[name] !== undefined) {
      return value[name];
    }
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmpty(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}
