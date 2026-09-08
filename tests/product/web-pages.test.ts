import { expect, it } from "vitest";
import { createExecutor } from "../../src/scan/execute.js";
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
// Omitting issue 6+, collapsing everything, or interpolating raw title/prompt breaks these checks.
it("renders all pipeline issues with five open, remediation, prompts and incomplete coverage", async () => {
  const result = await report();
  expect(result.issues).toHaveLength(7);
  const html = renderReport(result);
  expect(html.match(/<details data-issue/g)).toHaveLength(7);
  expect(html.match(/<details data-issue open/g)).toHaveLength(5);
  expect(html).toContain("2 more important issues");
  expect(html).toContain("Scan incomplete");
  expect(html).toContain("Check coverage");
  expect(html).toContain(escaped);
  expect(html).not.toContain(hostile);
  expect(html).not.toContain(privateText);
  expect(html).toContain(result.repository.commit);
  for (const issue of result.issues) {
    expect(html).toContain(issue.remediation);
    expect(html).toContain(issue.verification);
  }
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
