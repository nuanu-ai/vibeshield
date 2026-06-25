import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { auditInventory, parseJuiceShopChallenges } from "../scripts/deep-benchmark-inventory.js";

describe("deep benchmark inventory", () => {
  it("parses Juice Shop challenge names, categories, and keys", () => {
    const challenges = parseJuiceShopChallenges(`
---
-
  name: 'Bjoern''s Favorite Pet'
  category: 'Broken Authentication'
  key: resetPasswordBjoernOwaspChallenge
-
  name: "XXE Data Access"
  category: XXE
  key: xxeFileDisclosureChallenge
`);

    expect(challenges).toEqual([
      {
        key: "resetPasswordBjoernOwaspChallenge",
        name: "Bjoern's Favorite Pet",
        category: "Broken Authentication",
      },
      {
        key: "xxeFileDisclosureChallenge",
        name: "XXE Data Access",
        category: "XXE",
      },
    ]);
  });

  it("audits category coverage against checked-in ground truth ids", async () => {
    const sourceRoot = await mkdtemp(path.join(os.tmpdir(), "vibeshield-inventory-"));
    await writeFile(
      path.join(sourceRoot, "challenges.yml"),
      `
---
-
  name: 'Login Admin'
  category: 'Injection'
  key: loginAdminChallenge
-
  name: 'Score Board'
  category: 'Miscellaneous'
  key: scoreBoardChallenge
`,
    );

    const summaries = await auditInventory(
      {
        version: 1,
        repositories: [
          {
            id: "juice-shop",
            name: "Juice Shop fixture",
            source: { kind: "juice-shop-challenges", relativePath: "challenges.yml" },
            categoryCoverage: {
              Injection: { groundTruthIds: ["juice.sql-injection"] },
              Miscellaneous: { limitation: "runtime-only product goal" },
            },
          },
        ],
      },
      {
        failOnLimitations: false,
        failOnGaps: false,
        sources: { "juice-shop": sourceRoot },
        expectationIds: new Set(["juice.sql-injection"]),
      },
    );

    expect(summaries).toEqual([
      {
        repositoryId: "juice-shop",
        name: "Juice Shop fixture",
        challengeCount: 2,
        categoryCount: 2,
        coveredCategories: 1,
        limitationCategories: 1,
        challengeGapCategories: 0,
        challengeGaps: 0,
        errors: [],
      },
    ]);
  });

  it("can fail when documented limitations remain", async () => {
    const sourceRoot = await mkdtemp(path.join(os.tmpdir(), "vibeshield-inventory-"));
    await writeFile(
      path.join(sourceRoot, "challenges.yml"),
      `
---
-
  name: 'Score Board'
  category: 'Miscellaneous'
  key: scoreBoardChallenge
`,
    );

    const summaries = await auditInventory(
      {
        version: 1,
        repositories: [
          {
            id: "juice-shop",
            name: "Juice Shop fixture",
            source: { kind: "juice-shop-challenges", relativePath: "challenges.yml" },
            categoryCoverage: {
              Miscellaneous: { limitation: "runtime-only product goal" },
            },
          },
        ],
      },
      {
        failOnLimitations: true,
        failOnGaps: false,
        sources: { "juice-shop": sourceRoot },
        expectationIds: new Set(),
      },
    );

    expect(summaries[0]?.errors).toEqual([
      "category Miscellaneous has documented limitation: runtime-only product goal",
    ]);
  });

  it("can report and fail open challenge-level gaps separately from limitations", async () => {
    const sourceRoot = await mkdtemp(path.join(os.tmpdir(), "vibeshield-inventory-"));
    await writeFile(
      path.join(sourceRoot, "challenges.yml"),
      `
---
-
  name: 'Login Admin'
  category: 'Injection'
  key: loginAdminChallenge
`,
    );

    const inventory = {
      version: 1 as const,
      repositories: [
        {
          id: "juice-shop",
          name: "Juice Shop fixture",
          source: { kind: "juice-shop-challenges" as const, relativePath: "challenges.yml" },
          categoryCoverage: {
            Injection: {
              groundTruthIds: ["juice.sql-injection"],
              challengeGaps: ["NoSQL and SSTi challenge-level expectations are not mapped yet."],
            },
          },
        },
      ],
    };

    const defaultSummaries = await auditInventory(inventory, {
      failOnLimitations: false,
      failOnGaps: false,
      sources: { "juice-shop": sourceRoot },
      expectationIds: new Set(["juice.sql-injection"]),
    });
    const strictSummaries = await auditInventory(inventory, {
      failOnLimitations: false,
      failOnGaps: true,
      sources: { "juice-shop": sourceRoot },
      expectationIds: new Set(["juice.sql-injection"]),
    });

    expect(defaultSummaries[0]).toMatchObject({
      coveredCategories: 1,
      limitationCategories: 0,
      challengeGapCategories: 1,
      challengeGaps: 1,
      errors: [],
    });
    expect(strictSummaries[0]?.errors).toEqual([
      "category Injection has open challenge gap: NoSQL and SSTi challenge-level expectations are not mapped yet.",
    ]);
  });
});
