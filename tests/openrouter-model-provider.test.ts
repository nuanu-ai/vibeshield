import { describe, expect, it } from "vitest";
import {
  DEFAULT_REMEDIATION_MODEL,
  OpenRouterModelProvider,
} from "../src/adapters/openrouter-model-provider.js";
import type { ModelEnhanceBatchInput } from "../src/ports/model-provider.js";

describe("OpenRouterModelProvider", () => {
  it("posts one remediation batch to the configured model and parses structured actions", async () => {
    const requests: Array<{ url: string; init: RequestInit }> = [];
    const provider = new OpenRouterModelProvider({
      apiKey: "test-key",
      model: "anthropic/claude-sonnet-4.6",
      fetchFn: async (url, init) => {
        requests.push({ url: String(url), init: init ?? {} });
        return jsonResponse({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  actions: [
                    {
                      candidateId: "action-1",
                      title: "Clear title",
                      risk: "Clear risk",
                      whyFixNow: "Clear urgency",
                      fixSteps: ["Patch the file"],
                      operationalSteps: ["Rotate the key"],
                      agentPrompt: "Patch src/config.ts:3",
                      verifySteps: ["Run tests"],
                    },
                  ],
                }),
              },
            },
          ],
        });
      },
    });

    const result = await provider.enhance(modelInput());

    expect(result).toEqual([
      {
        candidateId: "action-1",
        title: "Clear title",
        risk: "Clear risk",
        whyFixNow: "Clear urgency",
        fixSteps: ["Patch the file"],
        operationalSteps: ["Rotate the key"],
        agentPrompt: "Patch src/config.ts:3",
        verifySteps: ["Run tests"],
        fromCatalog: false,
      },
    ]);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe("https://openrouter.ai/api/v1/chat/completions");
    expect(requests[0]?.init.headers).toMatchObject({
      Authorization: "Bearer test-key",
      "Content-Type": "application/json",
    });
    const body = JSON.parse(String(requests[0]?.init.body));
    expect(body.model).toBe("anthropic/claude-sonnet-4.6");
    expect(body.response_format).toEqual({ type: "json_object" });
    expect(body.messages[1].content).toContain("action-1");
  });

  it("uses the default Sonnet model, accepts fenced JSON, and returns null when invalid", async () => {
    const unavailable = new OpenRouterModelProvider();
    await expect(unavailable.isAvailable()).resolves.toBe(false);
    await expect(unavailable.enhance(modelInput())).resolves.toBeNull();

    const fenced = new OpenRouterModelProvider({
      apiKey: "test-key",
      fetchFn: async () =>
        jsonResponse({
          choices: [
            {
              message: {
                content:
                  '```json\n{"actions":[{"candidateId":"action-1","title":"T","risk":"R","whyFixNow":"W","fixSteps":["F"],"operationalSteps":[],"agentPrompt":"P","verifySteps":["V"]}]}\n```',
              },
            },
          ],
        }),
    });
    await expect(fenced.isAvailable()).resolves.toBe(true);
    await expect(fenced.enhance(modelInput())).resolves.toMatchObject([
      { candidateId: "action-1", title: "T", fromCatalog: false },
    ]);

    const repaired = new OpenRouterModelProvider({
      apiKey: "test-key",
      fetchFn: async () =>
        jsonResponse({
          choices: [
            {
              message: {
                content:
                  "{actions:[{candidateId:'action-1',title:'Repaired',risk:'R',whyFixNow:'W',fixSteps:['F'],operationalSteps:[],agentPrompt:'P',verifySteps:['V'],}],}",
              },
            },
          ],
        }),
    });
    await expect(repaired.enhance(modelInput())).resolves.toMatchObject([
      { candidateId: "action-1", title: "Repaired", fromCatalog: false },
    ]);

    const aliased = new OpenRouterModelProvider({
      apiKey: "test-key",
      fetchFn: async () =>
        jsonResponse({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  remediations: [
                    {
                      candidate_id: "action-1",
                      title: "Alias title",
                      risk: "Alias risk",
                      why_fix_now: "Alias urgency",
                      steps: ["Patch it"],
                      prompt: "Patch src/config.ts:3",
                      verification: ["Run tests"],
                    },
                  ],
                }),
              },
            },
          ],
        }),
    });
    await expect(aliased.enhance(modelInput())).resolves.toMatchObject([
      {
        candidateId: "action-1",
        title: "Alias title",
        operationalSteps: [],
        fromCatalog: false,
      },
    ]);

    const invalid = new OpenRouterModelProvider({
      apiKey: "test-key",
      fetchFn: async () => jsonResponse({ choices: [{ message: { content: "{not json}" } }] }),
    });
    await expect(invalid.enhance(modelInput())).resolves.toBeNull();

    const requests: RequestInit[] = [];
    const ok = new OpenRouterModelProvider({
      apiKey: "test-key",
      fetchFn: async (_url, init) => {
        requests.push(init ?? {});
        return jsonResponse({ choices: [{ message: { content: '{"actions":[]}' } }] });
      },
    });
    await ok.enhance({ repositoryName: "repo", actions: [] });
    await ok.enhance(modelInput());
    expect(JSON.parse(String(requests[0]?.body)).model).toBe(DEFAULT_REMEDIATION_MODEL);
  });
});

function modelInput(): ModelEnhanceBatchInput {
  return {
    repositoryName: "repo",
    actions: [
      {
        candidateId: "action-1",
        remediationKey: "live-secret-in-source",
        priorityScore: 100,
        verdictImpact: "blocks-deploy",
        summary: {
          totalFindings: 1,
          includedFindings: 1,
          omittedFindings: 0,
          totalAffectedFiles: 1,
          includedAffectedFiles: 1,
          omittedAffectedFiles: 0,
          rules: [{ value: "stripe-access-token", count: 1 }],
          tools: [{ value: "gitleaks", count: 1 }],
          severities: [{ value: "critical", count: 1 }],
        },
        affectedFiles: ["src/config.ts"],
        catalogRemediation: {
          candidateId: "action-1",
          title: "Remove the committed secret",
          risk: "Risk",
          whyFixNow: "Now",
          fixSteps: ["Remove it"],
          operationalSteps: ["Rotate it"],
          agentPrompt: "Patch src/config.ts:3",
          verifySteps: ["Run VibeShield again"],
          fromCatalog: true,
        },
        findings: [
          {
            findingId: "finding-1",
            sourceTool: "gitleaks",
            ruleId: "stripe-access-token",
            category: "secret",
            severity: "critical",
            filePath: "src/config.ts",
            startLine: 3,
            snippet: 'stripeSecret: "***REDACTED***"',
          },
        ],
      },
    ],
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
