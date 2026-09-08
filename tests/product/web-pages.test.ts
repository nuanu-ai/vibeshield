import { expect, it } from "vitest";
import type { Report } from "../../src/scan/contracts.js";
import { createExecutor } from "../../src/scan/execute.js";
import type { RemediationKey } from "../../src/scan/remediation.js";
import {
  renderHome,
  renderProgress,
  renderReport,
  renderUnavailable,
} from "../../src/web/pages.js";
import {
  ControlledSandbox,
  fixtureProvenance,
  fixtureSnapshot,
  privateText,
  rawOsv,
} from "../support/controlled-sandbox.js";

const hostile = '<img src=x onerror=alert(1)> & "quoted"';
const escaped = "&lt;img src=x onerror=alert(1)&gt; &amp; &quot;quoted&quot;";
async function report() {
  const sandbox = new ControlledSandbox();
  const osv = rawOsv();
  const packages = osv.output.results[0]?.packages;
  const original = packages?.[0];
  const advisory = original?.vulnerabilities[0];
  if (!packages || !original || !advisory) throw new Error("Incomplete OSV fixture");
  advisory.summary = hostile;
  for (const name of ["package-two", "package-three"]) {
    const next = structuredClone(original);
    next.package.name = name;
    const affected = next.vulnerabilities[0]?.affected[0];
    if (!affected) throw new Error("Incomplete OSV fixture");
    affected.package.name = name;
    packages.push(next);
  }
  sandbox.outputs.set("osv", osv);
  sandbox.releaseAll();
  return createExecutor(sandbox, fixtureProvenance)(
    { id: "render", url: fixtureSnapshot.url },
    new AbortController().signal,
    () => {},
  );
}
const esc = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char,
  );
/** Everything a reader sees without opening anything. */
function surface(html: string): string {
  return html.replace(/<details[\s\S]*?<\/details>/g, "");
}

// Three dependency advisories that share one upgrade are one job, not three cards.
it("shows one job per fix while keeping every location and prompt", async () => {
  const value = await report();
  expect(value.issues).toHaveLength(7);
  const html = renderReport(value);
  expect(html.match(/<article data-fix/g)).toHaveLength(5);
  for (const issue of value.issues) {
    for (const location of issue.locations)
      expect(html).toContain(`${location.path}:${location.line}`);
    for (const line of issue.evidence) expect(html).toContain(esc(line));
    expect(html).toContain(esc(issue.title));
    expect(html).toContain(issue.remediation);
    expect(html).toContain(issue.verification);
  }
  expect(html).toContain(escaped);
  expect(html).not.toContain(hostile);
  expect(html).not.toContain(privateText);
});

// Presentation must never cost a job. Six fixes still means six jobs on the page.
it("keeps every job on the page and opens the first five", async () => {
  const value = await report();
  const keys: RemediationKey[] = [
    "secret-rotation",
    "dependency-upgrade",
    "command-input",
    "sql-input",
    "path-url-validation",
    "unsafe-deserialization",
    "jwt-validation",
  ];
  const spread: Report = {
    ...value,
    issues: value.issues.map((issue, index) => ({
      ...issue,
      remediationKey: keys[index] ?? "workflow-privilege",
    })),
  };
  const html = renderReport(spread);
  expect(html.match(/<article data-fix/g)).toHaveLength(7);
  expect(html.match(/<article data-fix open/g)).toHaveLength(5);
  expect(html).toContain("2 more");
});

// Tool names, versions, rule identifiers and coverage states belong behind a
// disclosure. The open page is what to do, not how we found it.
it("keeps machinery out of the page a reader sees first", async () => {
  const value = await report();
  const open = surface(renderReport(value));
  for (const machinery of [
    "gitleaks",
    "opengrep",
    "osv",
    "trivy",
    "zizmor",
    "8.30.0",
    "1.25.0",
    "GHSA",
    "degraded",
    "coverage",
    "remediation",
  ])
    expect(open.toLowerCase()).not.toContain(machinery.toLowerCase());
  expect(open).not.toContain(value.provenance.image);
  expect(open).not.toContain(value.repository.commit);
});

// A count is not an instruction. The first line names the first thing to do.
it("leads with the first job rather than a total", async () => {
  const value = await report();
  const html = renderReport(value);
  const heading = /<h1[^>]*>([\s\S]*?)<\/h1>/.exec(html)?.[1] ?? "";
  expect(heading).not.toMatch(/\d+\s+(important\s+)?issues?/i);
  const firstCard = /<article data-fix open><h2[^>]*>([\s\S]*?)<\/h2>/.exec(html)?.[1] ?? "";
  expect(firstCard).not.toContain(heading);
  expect(html.indexOf("<article data-fix")).toBeLessThan(html.indexOf("What we looked at"));
});

it("escapes every report text field and progress errors, with external assets only", async () => {
  const value = await report();
  const poison = (input: unknown): unknown => {
    if (typeof input === "string") return hostile;
    if (Array.isArray(input)) return input.map(poison);
    if (input && typeof input === "object")
      return Object.fromEntries(Object.entries(input).map(([key, item]) => [key, poison(item)]));
    return input;
  };
  const reportHtml = renderReport(poison(value) as typeof value);
  const pages = [
    reportHtml,
    renderHome(hostile),
    renderProgress({
      id: "opaque",
      url: hostile,
      createdAt: 1,
      status: "failed",
      failure: "internal",
      stages: [{ stage: "acquire", status: "failed", message: hostile }],
    }),
    renderUnavailable(),
  ];
  for (const html of pages) {
    expect(html).not.toContain("<img");
    expect(html).not.toMatch(/<style|<script(?! src=)/);
    expect(html).toContain('<script src="/assets/app.js" defer>');
    expect(html).toContain('href="/assets/app.css"');
  }
  expect(reportHtml.match(/&lt;img/g)?.length).toBeGreaterThan(30);
  expect(pages[2]).toContain(escaped);
});

it("keeps clean and incomplete empty results distinct, and unknown results actionable", async () => {
  const value = await report();
  value.issues = [];
  value.incomplete = true;
  expect(renderReport(value)).toContain("Scan incomplete");
  expect(renderReport(value)).not.toContain("No important problems found");
  value.incomplete = false;
  expect(renderReport(value)).toContain("No important problems found by the completed checks");
  expect(renderUnavailable()).toContain('href="/"');
});

// "waiting — Waiting." is the machine talking to itself.
it("shows what each step is doing instead of its status word", () => {
  const html = renderProgress({
    id: "opaque",
    url: "https://github.com/owner/repo",
    createdAt: 0,
    status: "running",
    stages: [
      { stage: "prepare", status: "completed", message: "Clean machine ready." },
      { stage: "osv", status: "waiting", message: "" },
    ],
  });
  expect(html).toContain("Clean machine ready.");
  expect(html.replace(/<[^>]*>/g, " ")).not.toMatch(/completed|waiting/i);
});

// Everything published is high severity, so the tiebreaker decided the order:
// a workflow note outranked a leaked credential because ".github" sorts first.
it("orders jobs by what to do first, not by where the file sits", async () => {
  const value = await report();
  const blocks = renderReport(value).split("<article data-fix").slice(1);
  const rankOf = (marker: string) => blocks.findIndex((block) => block.includes(marker)) + 1;
  expect(rankOf("A credential pattern was detected")).toBe(1);
  expect(rankOf("flow: app.ts:2")).toBe(2);
  expect(rankOf("zizmor template-injection")).toBe(3);
  expect(rankOf("lodash@4.17.20")).toBe(4);
  expect(rankOf("KSV-0017")).toBe(5);
});

// A key in shipped code is not the same job as a key in a test fixture, and a
// reader should not have to read ten paths to find the one that ships.
it("puts application files ahead of test files and says how many are tests", async () => {
  const value = await report();
  const first = value.issues[0];
  if (!first) throw new Error("Expected a fixture issue");
  const html = renderReport({
    ...value,
    issues: [
      {
        ...first,
        locations: [
          { path: "src/buy.test.ts", line: 12 },
          { path: "src/checkout.spec.ts", line: 3 },
          { path: "src/buy.ts", line: 46 },
        ],
      },
    ],
  });
  expect(html.indexOf("src/buy.ts:46")).toBeLessThan(html.indexOf("src/buy.test.ts:12"));
  expect(html.indexOf("src/buy.ts:46")).toBeLessThan(html.indexOf("src/checkout.spec.ts:3"));
  expect(html).toContain("2 of them tests");
});

// A reader who does not open files should never be shown one. Paths, line
// numbers and code live in the prompt and behind a disclosure.
it("keeps file paths and code out of the page a reader sees first", async () => {
  const value = await report();
  const open = surface(renderReport(value));
  for (const issue of value.issues)
    for (const location of issue.locations)
      expect(open).not.toContain(`${location.path}:${location.line}`);
  expect(open).not.toContain("<pre");
  expect(open).not.toContain("<code");
});
