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
        sources: { "juice-shop": sourceRoot },
        expectationIds: new Set(),
      },
    );

    expect(summaries[0]?.errors).toEqual([
      "category Miscellaneous has documented limitation: runtime-only product goal",
    ]);
  });
});
