import { createWriteStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import PDFDocument from "pdfkit";
import type {
  AttackHypothesesArtifact,
  AttackHypothesisPriority,
  AttackHypothesisRecord,
  BaselineObservation,
  BaselineSummaryArtifact,
  RepositoryMapArtifact,
} from "../artifacts/contracts.js";
import type { ScanRunState } from "../run/types.js";

const severityOrder = ["critical", "high", "medium", "low", "info", "unknown"] as const;
const priorityOrder: AttackHypothesisPriority[] = ["P0", "P1", "P2", "P3"];

type Severity = (typeof severityOrder)[number];
type VerdictLevel = "critical" | "review" | "clean";

interface FinalReportPaths {
  markdownPath: string;
  pdfPath: string;
}

interface ReportFact {
  label: string;
  value: string;
}

interface ReportCard {
  agentPrompt: string;
  category: string;
  color: string;
  confidenceNote: string;
  confirmed: boolean;
  facts: ReportFact[];
  title: string;
  why: string;
}

interface ReportCardGroup {
  cards: ReportCard[];
  color: string;
  label: string;
}

interface ReportVerdict {
  color: string;
  level: VerdictLevel;
  subline: string;
  title: string;
}

interface FinalReportModel {
  confirmedGroups: ReportCardGroup[];
  counts: {
    confirmed: number;
    leads: number;
    needsNow: number;
  };
  generatedAt: string;
  leadGroups: ReportCardGroup[];
  limitations: string[];
  repo: {
    commitShaFull: string;
    commitShaShort: string;
    name: string;
    url: string;
  };
  runId: string;
  startHere: string[];
  summary: string;
  verdict: ReportVerdict;
}

interface DeterministicFinding {
  confidence: string;
  evidence: string[];
  kind: string;
  message: string;
  occurrences: number;
  severity: Severity;
}

export async function writeFinalReport(input: {
  markdownPath: string;
  pdfPath: string;
  run: ScanRunState;
}): Promise<FinalReportPaths> {
  const runDir = path.dirname(input.markdownPath);
  const [baseline, repositoryMap, attackHypotheses] = await Promise.all([
    readArtifact<BaselineSummaryArtifact>(runDir, input.run.artifacts.baseline_summary),
    readArtifact<RepositoryMapArtifact>(runDir, input.run.artifacts.repository_map),
    readArtifact<AttackHypothesesArtifact>(runDir, input.run.artifacts.attack_hypotheses),
  ]);
  if (baseline === null && repositoryMap === null && attackHypotheses === null) {
    throw new Error("Cannot render final report without any report input artifacts.");
  }
  const model = buildFinalReportModel({
    attackHypotheses,
    baseline,
    repositoryMap,
    run: input.run,
  });

  await writeFile(input.markdownPath, `${renderMarkdown(model)}\n`, "utf8");
  await writePdf(input.pdfPath, model);

  return {
    markdownPath: path.basename(input.markdownPath),
    pdfPath: path.basename(input.pdfPath),
  };
}

async function readArtifact<T>(
  runDir: string,
  relativePath: string | undefined,
): Promise<T | null> {
  if (relativePath === undefined) {
    return null;
  }

  try {
    return JSON.parse(await readFile(path.join(runDir, relativePath), "utf8")) as T;
  } catch {
    return null;
  }
}

function buildFinalReportModel(input: {
  attackHypotheses: AttackHypothesesArtifact | null;
  baseline: BaselineSummaryArtifact | null;
  repositoryMap: RepositoryMapArtifact | null;
  run: ScanRunState;
}): FinalReportModel {
  const deterministicFindings = collectDeterministicFindings(input.baseline);
  const hypotheses = input.attackHypotheses?.hypotheses ?? [];
  const repoName = repositoryName(input.run.source.url);
  const commitShaFull = input.run.commit_sha ?? "unknown";
  const commitShaShort = input.run.commit_sha === undefined ? "unknown" : shortSha(commitShaFull);

  const needsNow = deterministicFindings.filter(
    (finding) => finding.severity === "critical" || finding.severity === "high",
  ).length;
  const counts = {
    confirmed: deterministicFindings.length,
    leads: hypotheses.length,
    needsNow,
  };

  const executiveText =
    input.attackHypotheses?.executive_summary.text?.trim() ??
    input.repositoryMap?.summary.text?.trim() ??
    "";

  return {
    confirmedGroups: severityOrder
      .map((severity) => ({
        cards: deterministicFindings
          .filter((finding) => finding.severity === severity)
          .map((finding) => deterministicCard(finding, repoName)),
        color: severityColor(severity),
        label: severityLabel(severity),
      }))
      .filter((group) => group.cards.length > 0),
    counts,
    generatedAt: new Date().toISOString(),
    leadGroups: priorityOrder
      .map((priority) => ({
        cards: hypotheses
          .filter((hypothesis) => hypothesis.priority === priority)
          .sort(compareHypotheses)
          .map((hypothesis) => hypothesisCard(hypothesis, repoName)),
        color: priorityColor(priority),
        label: priorityLabel(priority),
      }))
      .filter((group) => group.cards.length > 0),
    limitations:
      input.attackHypotheses === null
        ? ["Attack hypotheses were not available when this best-effort report was rendered."]
        : cleanList(input.attackHypotheses.executive_summary.limitations ?? []),
    repo: {
      commitShaFull,
      commitShaShort,
      name: repoName,
      url: input.run.source.url,
    },
    runId: input.run.run_id,
    startHere: cleanList(input.attackHypotheses?.validation_roadmap?.first_pass ?? []).slice(0, 5),
    summary: executiveText === "" ? fallbackSummary(repoName, commitShaShort) : executiveText,
    verdict: buildVerdict({ counts, hypotheses }),
  };
}

function buildVerdict(input: {
  counts: { confirmed: number; leads: number; needsNow: number };
  hypotheses: AttackHypothesisRecord[];
}): ReportVerdict {
  const { confirmed, leads, needsNow } = input.counts;
  const p0 = input.hypotheses.filter((hypothesis) => hypothesis.priority === "P0").length;
  const p1 = input.hypotheses.filter((hypothesis) => hypothesis.priority === "P1").length;

  if (needsNow > 0 || p0 > 0) {
    const subline =
      needsNow > 0
        ? `${pluralize(needsNow, "confirmed issue")} ${needsNow === 1 ? "needs" : "need"} fixing right now${
            leads > 0 ? `, and ${pluralize(leads, "lead")} worth checking` : ""
          }.`
        : `Nothing is confirmed yet, but ${pluralize(leads, "unconfirmed lead")} ${
            leads === 1 ? "looks" : "look"
          } serious — check ${leads === 1 ? "it" : "them"} before you rely on this code.`;
    return { color: colors.critical, level: "critical", subline, title: "Not safe yet" };
  }

  if (confirmed > 0 || p1 > 0 || leads > 0) {
    const parts: string[] = [];
    if (confirmed > 0) {
      parts.push(pluralize(confirmed, "confirmed issue"));
    }
    if (leads > 0) {
      parts.push(pluralize(leads, "lead"));
    }
    const tail = parts.length > 0 ? joinAnd(parts) : "a few things";
    return {
      color: colors.medium,
      level: "review",
      subline: `Nothing critical, but ${tail} worth a look before you rely on this code.`,
      title: "Worth a closer look",
    };
  }

  return {
    color: colors.low,
    level: "clean",
    subline:
      "No confirmed issues and no high-risk leads. This isn't a guarantee — automated checks can miss things, so keep reviewing as you build.",
    title: "Nothing critical found",
  };
}

function deterministicCard(finding: DeterministicFinding, repoName: string): ReportCard {
  const category = deterministicCategory(finding.kind);
  const action = deterministicAction(finding.kind);
  const where = compactList(finding.evidence);
  const facts: ReportFact[] = [];
  pushFact(facts, "Where", where || "not reported");
  pushFact(facts, "What to do", action);
  return {
    agentPrompt: normalizeWhitespace(
      `In ${repoName}, fix this ${category.toLowerCase()}: ${finding.message} ${action}${
        where === "" ? "" : ` Affected: ${where}.`
      }`,
    ),
    category,
    color: severityColor(finding.severity),
    confidenceNote: `${finding.confidence} confidence`,
    confirmed: true,
    facts,
    title: `${finding.message}${finding.occurrences > 1 ? ` (${finding.occurrences} places)` : ""}`,
    why: "",
  };
}

function hypothesisCard(hypothesis: AttackHypothesisRecord, repoName: string): ReportCard {
  const where = compactList([hypothesis.target_surface, ...(hypothesis.target_ids ?? [])]);
  const checks = compactList(hypothesis.validation_plan);
  const fix = compactList(hypothesis.likely_remediation_if_confirmed ?? []);
  const facts: ReportFact[] = [];
  pushFact(facts, "Where to look", where);
  pushFact(facts, "How it could happen", hypothesis.attack_vector);
  pushFact(facts, "How to check", checks);
  pushFact(facts, "How to fix it", fix);
  pushFact(facts, "Evidence", compactList(hypothesis.supporting_map_evidence));
  pushFact(facts, "Still unknown", compactList(hypothesis.missing_facts_to_validate));
  return {
    agentPrompt: normalizeWhitespace(
      `In ${repoName}, check a possible security issue: ${hypothesis.title}. ${hypothesis.potential_impact}${
        where === "" ? "" : ` Where to look: ${where}.`
      }${checks === "" ? "" : ` How to check: ${checks}.`}${
        fix === "" ? "" : ` If it is real, fix it by: ${fix}.`
      }`,
    ),
    category: "",
    color: priorityColor(hypothesis.priority),
    confidenceNote: `${hypothesis.confidence} confidence`,
    confirmed: false,
    facts,
    title: hypothesis.title,
    why: hypothesis.potential_impact,
  };
}

function deterministicCategory(kind: string): string {
  switch (kind) {
    case "secret":
      return "Exposed secret";
    case "dependency":
      return "Vulnerable dependency";
    case "supply-chain":
      return "Supply-chain risk";
    case "iac":
      return "Risky infrastructure setting";
    case "workflow":
      return "CI workflow risk";
    default:
      return "Issue";
  }
}

function deterministicAction(kind: string): string {
  switch (kind) {
    case "secret":
      return "Rotate this secret now, then remove it from the code and from git history.";
    case "dependency":
      return "Update the affected package to a patched version, then re-test.";
    case "supply-chain":
      return "Pin this dependency to a trusted, fixed version and review its source.";
    case "iac":
      return "Change this setting to a safer default.";
    case "workflow":
      return "Harden the workflow: pin actions by commit SHA and limit token permissions.";
    default:
      return "Review and fix this issue.";
  }
}

function collectDeterministicFindings(
  baseline: BaselineSummaryArtifact | null,
): DeterministicFinding[] {
  const findings = new Map<string, DeterministicFinding>();
  for (const tool of baseline?.tools ?? []) {
    for (const observation of tool.observations) {
      const severity = normalizeSeverity(observation);
      if (severity === "info") {
        continue;
      }
      const key = [observation.kind, severity, observation.message].join("\0");
      const existing = findings.get(key);
      if (existing === undefined) {
        findings.set(key, {
          confidence: observation.confidence,
          evidence: [...observation.evidence],
          kind: observation.kind,
          message: observation.message,
          occurrences: 1,
          severity,
        });
        continue;
      }
      existing.occurrences += 1;
      existing.evidence = [...new Set([...existing.evidence, ...observation.evidence])];
      if (confidenceRank(observation.confidence) < confidenceRank(existing.confidence)) {
        existing.confidence = observation.confidence;
      }
    }
  }

  return [...findings.values()].sort(
    (left, right) =>
      severityOrder.indexOf(left.severity) - severityOrder.indexOf(right.severity) ||
      left.kind.localeCompare(right.kind) ||
      left.message.localeCompare(right.message),
  );
}

function fallbackSummary(repoName: string, commitShaShort: string): string {
  return `This report reviews ${repoName} at commit ${commitShaShort}. It combines automated security scanners with an AI review of the code. The confirmed issues and unconfirmed leads are listed below.`;
}

function renderMarkdown(model: FinalReportModel): string {
  const lines = [
    "# Security Report",
    "",
    `_${escapeMarkdown(model.repo.name)}_`,
    "",
    `## Status: ${model.verdict.title}`,
    "",
    model.verdict.subline,
    "",
    "## Summary",
    "",
    model.summary,
    "",
    "## Snapshot",
    "",
    `- Needs you now: ${model.counts.needsNow}`,
    `- Confirmed issues: ${model.counts.confirmed}`,
    `- Unconfirmed leads: ${model.counts.leads}`,
    "",
  ];

  if (model.startHere.length > 0) {
    lines.push("## Start here", "");
    model.startHere.forEach((entry, index) => {
      lines.push(`${index + 1}. ${escapeMarkdown(entry)}`);
    });
    lines.push("");
  }

  lines.push(
    "## Issues to fix",
    "",
    ...renderCardGroupsMarkdown(
      model.confirmedGroups,
      "No issues were confirmed by the automated scanners. That isn't a clean bill of health — also read the leads below.",
    ),
    "## Leads to check",
    "",
    "These are unconfirmed — possible problems the AI review flagged for you to verify, not proven bugs.",
    "",
    ...renderCardGroupsMarkdown(
      model.leadGroups,
      "The AI review didn't flag any leads worth checking.",
    ),
  );

  if (model.limitations.length > 0) {
    lines.push("## What we couldn't fully check", "");
    for (const limitation of model.limitations) {
      lines.push(`- ${escapeMarkdown(limitation)}`);
    }
    lines.push("");
  }

  lines.push(
    "---",
    "",
    `Repository: ${model.repo.url}`,
    `Commit: ${model.repo.commitShaShort}`,
    `Run ID: ${model.runId}`,
    `Generated: ${model.generatedAt}`,
  );

  return normalizeMarkdownSpacing(lines).join("\n");
}

function renderCardGroupsMarkdown(groups: ReportCardGroup[], emptyText: string): string[] {
  if (groups.length === 0) {
    return [emptyText, ""];
  }

  return groups.flatMap((group) => [
    `### ${group.label}`,
    "",
    ...group.cards.flatMap(renderCardMarkdown),
  ]);
}

function renderCardMarkdown(card: ReportCard): string[] {
  const tags = [card.confirmed ? "Confirmed" : "Unconfirmed lead"];
  if (card.category !== "") {
    tags.push(card.category);
  }
  if (card.confidenceNote !== "") {
    tags.push(card.confidenceNote);
  }

  const lines = [
    `#### ${escapeMarkdown(card.title)}`,
    "",
    `_${escapeMarkdown(tags.join(" · "))}_`,
    "",
  ];
  if (card.why !== "") {
    lines.push(escapeMarkdown(card.why), "");
  }
  for (const fact of card.facts) {
    lines.push(`- **${escapeMarkdown(fact.label)}:** ${escapeMarkdown(fact.value)}`);
  }
  lines.push("", "**Copy for your AI agent:**", "", "```text", card.agentPrompt, "```", "");
  return lines;
}

async function writePdf(pdfPath: string, model: FinalReportModel): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const doc = new PDFDocument({
      autoFirstPage: true,
      info: {
        Author: model.repo.name,
        Subject: `Security report for ${model.repo.name}`,
        Title: "Security Report",
      },
      margin: 48,
      size: "A4",
    });
    const stream = createWriteStream(pdfPath);
    stream.on("finish", resolve);
    stream.on("error", reject);
    doc.on("error", reject);
    doc.pipe(stream);
    renderPdf(doc, model);
    doc.end();
  });
}

function renderPdf(doc: PDFKit.PDFDocument, model: FinalReportModel): void {
  drawCover(doc, model);
  drawVerdictBanner(doc, model);

  drawSectionTitle(doc, "Summary", 96);
  drawParagraph(doc, model.summary, 11.5, colors.ink);
  drawMetricStrip(doc, model);

  if (model.startHere.length > 0) {
    drawSectionTitle(doc, "Start here", 96);
    model.startHere.forEach((entry, index) => {
      drawMutedLine(doc, `${index + 1}. ${entry}`);
    });
  }

  drawCardSection(
    doc,
    "Issues to fix",
    model.confirmedGroups,
    "No issues were confirmed by the automated scanners. That isn't a clean bill of health — also read the leads below.",
  );

  drawCardSection(
    doc,
    "Leads to check",
    model.leadGroups,
    "The AI review didn't flag any leads worth checking.",
    "These are unconfirmed — possible problems for you to verify, not proven bugs.",
  );

  if (model.limitations.length > 0) {
    drawSectionTitle(doc, "What we couldn't fully check", 80);
    for (const limitation of model.limitations) {
      drawMutedLine(doc, `- ${limitation}`);
    }
  }

  drawFooter(doc, model);
}

const colors = {
  background: "#F6F8FB",
  border: "#D8DEE9",
  critical: "#B42318",
  high: "#D92D20",
  info: "#2563EB",
  ink: "#111827",
  low: "#2E7D32",
  medium: "#B54708",
  muted: "#667085",
  navy: "#172554",
  panel: "#FFFFFF",
  unknown: "#667085",
};

function drawCover(doc: PDFKit.PDFDocument, model: FinalReportModel): void {
  doc.rect(0, 0, doc.page.width, doc.page.height).fill(colors.background);
  doc.rect(0, 0, doc.page.width, 150).fill(colors.navy);
  doc
    .fillColor("#FFFFFF")
    .font("Helvetica-Bold")
    .fontSize(30)
    .text("Security report", 48, 46, { width: pageWidth(doc) });
  doc
    .font("Helvetica")
    .fontSize(13)
    .fillColor("#DDE7FF")
    .text(model.repo.name, 48, doc.y + 4, { width: pageWidth(doc) });
  doc
    .font("Helvetica")
    .fontSize(10.5)
    .fillColor("#DDE7FF")
    .text("A plain-language read on what to fix before you rely on this code", 48, doc.y + 6, {
      width: pageWidth(doc),
    });
  doc.y = 178;
}

function drawVerdictBanner(doc: PDFKit.PDFDocument, model: FinalReportModel): void {
  const x = doc.page.margins.left;
  const width = pageWidth(doc);
  const innerWidth = width - 28;
  doc.font("Helvetica").fontSize(10.5);
  const sublineHeight = doc.heightOfString(model.verdict.subline, {
    lineGap: 2,
    width: innerWidth,
  });
  const boxHeight = 42 + sublineHeight;
  ensureSpace(doc, boxHeight + 12);
  const y = doc.y;
  doc.roundedRect(x, y, width, boxHeight, 12).fill(model.verdict.color);
  doc
    .fillColor("#FFFFFF")
    .font("Helvetica-Bold")
    .fontSize(16)
    .text(model.verdict.title, x + 14, y + 12, { width: innerWidth });
  doc
    .fillColor("#FFFFFF")
    .font("Helvetica")
    .fontSize(10.5)
    .text(model.verdict.subline, x + 14, y + 34, { lineGap: 2, width: innerWidth });
  doc.y = y + boxHeight + 14;
}

function drawMetricStrip(doc: PDFKit.PDFDocument, model: FinalReportModel): void {
  const metrics = [
    { label: "Needs you now", value: String(model.counts.needsNow) },
    { label: "Confirmed issues", value: String(model.counts.confirmed) },
    { label: "Unconfirmed leads", value: String(model.counts.leads) },
  ];
  const gap = 10;
  const width = (pageWidth(doc) - gap * 2) / 3;
  const y = doc.y + 8;
  metrics.forEach((metric, index) => {
    const x = doc.page.margins.left + index * (width + gap);
    doc.roundedRect(x, y, width, 70, 10).fillAndStroke(colors.panel, colors.border);
    doc
      .fillColor(colors.muted)
      .font("Helvetica")
      .fontSize(8)
      .text(metric.label.toUpperCase(), x + 14, y + 14);
    doc
      .fillColor(colors.ink)
      .font("Helvetica-Bold")
      .fontSize(20)
      .text(metric.value, x + 14, y + 31, { width: width - 28 });
  });
  doc.y = y + 88;
}

function drawCardGroups(
  doc: PDFKit.PDFDocument,
  groups: ReportCardGroup[],
  emptyText: string,
): void {
  if (groups.length === 0) {
    drawMutedLine(doc, emptyText);
    return;
  }
  for (const group of groups) {
    const firstCard = group.cards[0];
    const firstHeight =
      firstCard === undefined
        ? 0
        : Math.min(cardLayout(doc, firstCard).height, pageContentHeight(doc));
    ensureSpace(doc, 52 + firstHeight);
    drawGroupLabel(doc, group.label, group.color, group.cards.length);
    group.cards.forEach((card, index) => {
      drawCard(doc, card, group.label, index === 0);
    });
  }
}

const cardLabelWidth = 88;

const cardGaps = {
  end: 14,
  fact: 7,
  meta: 4,
  pillRow: 28,
  prompt: 11,
  promptLabel: 12,
  why: 7,
};

interface CardLayout {
  factHeights: number[];
  height: number;
  meta: string;
  metaH: number;
  promptTextH: number;
  titleH: number;
  whyH: number;
}

function cardLayout(doc: PDFKit.PDFDocument, card: ReportCard): CardLayout {
  const bodyWidth = pageWidth(doc) - 14;
  const valueWidth = bodyWidth - cardLabelWidth;

  doc.font("Helvetica-Bold").fontSize(12);
  const titleH = doc.heightOfString(card.title, { lineGap: 2, width: bodyWidth });

  const meta = [card.category, card.confidenceNote].filter((entry) => entry !== "").join("  ·  ");
  let metaH = 0;
  if (meta !== "") {
    doc.font("Helvetica").fontSize(8);
    metaH = doc.heightOfString(meta, { width: bodyWidth });
  }

  let whyH = 0;
  if (card.why !== "") {
    doc.font("Helvetica").fontSize(9.5);
    whyH = doc.heightOfString(card.why, { lineGap: 1.5, width: bodyWidth });
  }

  const factHeights = card.facts.map((fact) => {
    doc.font("Helvetica").fontSize(9);
    const valueH = doc.heightOfString(fact.value, { lineGap: 1.5, width: valueWidth });
    doc.font("Helvetica-Bold").fontSize(7.5);
    const labelH = doc.heightOfString(fact.label.toUpperCase(), { width: cardLabelWidth - 8 });
    return Math.max(14, valueH, labelH);
  });

  let promptTextH = 0;
  if (card.agentPrompt.trim() !== "") {
    doc.font("Courier").fontSize(8.5);
    promptTextH = doc.heightOfString(card.agentPrompt, { lineGap: 1.5, width: bodyWidth - 24 });
  }

  let height = cardGaps.pillRow + titleH;
  if (metaH > 0) {
    height += cardGaps.meta + metaH;
  }
  if (whyH > 0) {
    height += cardGaps.why + whyH;
  }
  for (const factHeight of factHeights) {
    height += cardGaps.fact + factHeight;
  }
  if (promptTextH > 0) {
    height += cardGaps.prompt + cardGaps.promptLabel + promptTextH + 18;
  }
  height += cardGaps.end;

  return { factHeights, height, meta, metaH, promptTextH, titleH, whyH };
}

function drawCardSection(
  doc: PDFKit.PDFDocument,
  title: string,
  groups: ReportCardGroup[],
  emptyText: string,
  intro?: string,
): void {
  let keep = 58;
  if (intro !== undefined) {
    keep += 26;
  }
  const firstCard = groups[0]?.cards[0];
  keep +=
    firstCard === undefined
      ? 28
      : 52 + Math.min(cardLayout(doc, firstCard).height, pageContentHeight(doc));
  drawSectionTitle(doc, title, keep);
  if (intro !== undefined) {
    drawMutedLine(doc, intro);
  }
  drawCardGroups(doc, groups, emptyText);
}

function drawCard(
  doc: PDFKit.PDFDocument,
  card: ReportCard,
  groupLabel: string,
  keptWithLabel = false,
): void {
  const layout = cardLayout(doc, card);
  if (
    !keptWithLabel &&
    doc.y + layout.height > pageBottom(doc) &&
    layout.height <= pageContentHeight(doc)
  ) {
    doc.addPage();
  }

  const x = doc.page.margins.left;
  const bodyX = x + 14;
  const bodyWidth = pageWidth(doc) - 14;
  let cy = doc.y;

  doc.circle(x + 4, cy + 8, 4).fill(card.color);
  drawPill(doc, groupLabel, card.color, bodyX, cy);
  drawPill(
    doc,
    card.confirmed ? "Confirmed" : "Unconfirmed",
    card.confirmed ? colors.low : colors.unknown,
    bodyX + 96,
    cy,
  );
  cy += cardGaps.pillRow;

  doc
    .fillColor(colors.ink)
    .font("Helvetica-Bold")
    .fontSize(12)
    .text(card.title, bodyX, cy, { lineGap: 2, width: bodyWidth });
  cy += layout.titleH;

  if (layout.metaH > 0) {
    cy += cardGaps.meta;
    doc
      .fillColor(colors.muted)
      .font("Helvetica")
      .fontSize(8)
      .text(layout.meta, bodyX, cy, { width: bodyWidth });
    cy += layout.metaH;
  }

  if (layout.whyH > 0) {
    cy += cardGaps.why;
    doc
      .fillColor(colors.ink)
      .font("Helvetica")
      .fontSize(9.5)
      .text(card.why, bodyX, cy, { lineGap: 1.5, width: bodyWidth });
    cy += layout.whyH;
  }

  const valueX = bodyX + cardLabelWidth;
  const valueWidth = bodyWidth - cardLabelWidth;
  card.facts.forEach((fact, index) => {
    cy += cardGaps.fact;
    doc
      .fillColor(colors.muted)
      .font("Helvetica-Bold")
      .fontSize(7.5)
      .text(fact.label.toUpperCase(), bodyX, cy, { width: cardLabelWidth - 8 });
    doc
      .fillColor(colors.ink)
      .font("Helvetica")
      .fontSize(9)
      .text(fact.value, valueX, cy, { lineGap: 1.5, width: valueWidth });
    cy += layout.factHeights[index] ?? 14;
  });

  if (layout.promptTextH > 0) {
    cy += cardGaps.prompt;
    doc
      .fillColor(colors.muted)
      .font("Helvetica-Bold")
      .fontSize(7)
      .text("PASTE THIS TO YOUR AI AGENT", bodyX, cy);
    cy += cardGaps.promptLabel;
    const boxHeight = layout.promptTextH + 18;
    doc
      .roundedRect(bodyX, cy, bodyWidth, boxHeight, 8)
      .fillAndStroke(colors.background, colors.border);
    doc
      .fillColor(colors.ink)
      .font("Courier")
      .fontSize(8.5)
      .text(card.agentPrompt, bodyX + 12, cy + 9, { lineGap: 1.5, width: bodyWidth - 24 });
    cy += boxHeight;
  }

  cy += 7;
  doc
    .moveTo(bodyX, cy)
    .lineTo(doc.page.width - doc.page.margins.right, cy)
    .strokeColor(colors.border)
    .lineWidth(0.5)
    .stroke();
  doc.y = cy + 7;
}

function drawSectionTitle(doc: PDFKit.PDFDocument, title: string, keepWithNext = 80): void {
  ensureSpace(doc, keepWithNext);
  doc.moveDown(0.3);
  const x = doc.page.margins.left;
  doc
    .fillColor(colors.ink)
    .font("Helvetica-Bold")
    .fontSize(18)
    .text(title, x, doc.y, {
      width: pageWidth(doc),
    });
  doc
    .moveTo(x, doc.y + 6)
    .lineTo(doc.page.width - doc.page.margins.right, doc.y + 6)
    .lineWidth(1)
    .strokeColor(colors.border)
    .stroke();
  doc.moveDown(1.1);
}

function drawParagraph(doc: PDFKit.PDFDocument, text: string, size: number, color: string): void {
  const width = pageWidth(doc);
  ensureSpace(doc, doc.heightOfString(text, { width }) + 10);
  doc.fillColor(color).font("Helvetica").fontSize(size).text(text, doc.page.margins.left, doc.y, {
    align: "left",
    lineGap: 3,
    width,
  });
  doc.moveDown(0.5);
}

function drawGroupLabel(
  doc: PDFKit.PDFDocument,
  label: string,
  color: string,
  count: number,
): void {
  const text = `${label}  ${count}`;
  const width = Math.max(88, doc.widthOfString(text) + 26);
  doc.roundedRect(doc.page.margins.left, doc.y, width, 22, 11).fill(color);
  doc
    .fillColor("#FFFFFF")
    .font("Helvetica-Bold")
    .fontSize(9)
    .text(text.toUpperCase(), doc.page.margins.left + 13, doc.y + 7);
  doc.y += 30;
}

function drawMutedLine(doc: PDFKit.PDFDocument, text: string): void {
  ensureSpace(doc, 24);
  doc
    .fillColor(colors.muted)
    .font("Helvetica")
    .fontSize(9.5)
    .text(text, doc.page.margins.left, doc.y, { width: pageWidth(doc) });
  doc.moveDown(0.6);
}

function drawPill(
  doc: PDFKit.PDFDocument,
  text: string,
  color: string,
  x: number,
  y: number,
): void {
  doc.font("Helvetica-Bold").fontSize(7.2);
  const width = Math.max(68, doc.widthOfString(text.toUpperCase()) + 20);
  doc.roundedRect(x, y, width, 17, 8.5).fill(color);
  doc.fillColor("#FFFFFF").text(text.toUpperCase(), x + 10, y + 5, { width: width - 20 });
}

function drawFooter(doc: PDFKit.PDFDocument, model: FinalReportModel): void {
  drawSectionTitle(doc, "Run details", 80);
  drawKeyValue(doc, "Repository", model.repo.url);
  drawKeyValue(doc, "Commit", model.repo.commitShaShort);
  drawKeyValue(doc, "Run ID", model.runId);
  drawKeyValue(doc, "Generated", model.generatedAt);
}

function drawKeyValue(doc: PDFKit.PDFDocument, key: string, value: string): void {
  const x = doc.page.margins.left;
  const y = doc.y;
  doc.fillColor(colors.muted).font("Helvetica-Bold").fontSize(8).text(key.toUpperCase(), x, y);
  doc
    .fillColor(colors.ink)
    .font("Helvetica")
    .fontSize(10.5)
    .text(value, x + 98, y - 1, { width: pageWidth(doc) - 98 });
  doc.y += 22;
}

function ensureSpace(doc: PDFKit.PDFDocument, height: number): void {
  if (doc.y + height > pageBottom(doc)) {
    doc.addPage();
  }
}

function pageBottom(doc: PDFKit.PDFDocument): number {
  return doc.page.height - doc.page.margins.bottom - 8;
}

function pageContentHeight(doc: PDFKit.PDFDocument): number {
  return pageBottom(doc) - doc.page.margins.top;
}

function pageWidth(doc: PDFKit.PDFDocument): number {
  return doc.page.width - doc.page.margins.left - doc.page.margins.right;
}

function normalizeSeverity(observation: BaselineObservation): Severity {
  return severityOrder.includes(observation.severity as Severity)
    ? (observation.severity as Severity)
    : "unknown";
}

function compareHypotheses(left: AttackHypothesisRecord, right: AttackHypothesisRecord): number {
  return (
    confidenceRank(left.confidence) - confidenceRank(right.confidence) ||
    left.id.localeCompare(right.id)
  );
}

function confidenceRank(value: string): number {
  switch (value) {
    case "high":
      return 0;
    case "medium":
      return 1;
    case "low":
      return 2;
    default:
      return 99;
  }
}

function priorityLabel(priority: AttackHypothesisPriority): string {
  switch (priority) {
    case "P0":
      return "Critical";
    case "P1":
      return "High";
    case "P2":
      return "Medium";
    case "P3":
      return "Low";
  }
}

function priorityColor(priority: AttackHypothesisPriority): string {
  switch (priority) {
    case "P0":
      return colors.critical;
    case "P1":
      return colors.high;
    case "P2":
      return colors.medium;
    case "P3":
      return colors.low;
  }
}

function severityLabel(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    case "info":
      return "Info";
    case "unknown":
      return "Unknown";
  }
}

function severityColor(severity: Severity): string {
  switch (severity) {
    case "critical":
      return colors.critical;
    case "high":
      return colors.high;
    case "medium":
      return colors.medium;
    case "low":
      return colors.low;
    case "info":
      return colors.info;
    case "unknown":
      return colors.unknown;
  }
}

function repositoryName(url: string): string {
  const match = url.match(/github\.com\/(?<owner>[^/]+)\/(?<repo>[^/.]+)(?:\.git)?/i);
  if (match?.groups?.owner !== undefined && match.groups.repo !== undefined) {
    return `${match.groups.owner}/${match.groups.repo}`;
  }
  return url;
}

function shortSha(value: string): string {
  return value.length > 12 ? value.slice(0, 12) : value;
}

function pluralize(value: number, noun: string): string {
  return `${value} ${value === 1 ? noun : `${noun}s`}`;
}

function joinAnd(parts: string[]): string {
  if (parts.length <= 1) {
    return parts.join("");
  }
  return `${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}`;
}

function pushFact(facts: ReportFact[], label: string, value: string): void {
  if (value.trim() !== "") {
    facts.push({ label, value });
  }
}

function cleanList(values: readonly string[]): string[] {
  return values.map((value) => value.trim()).filter((value) => value !== "");
}

function compactList(values: readonly string[]): string {
  return values
    .map((value) => value.trim())
    .filter((value, index, array) => value !== "" && array.indexOf(value) === index)
    .join(", ");
}

function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function escapeMarkdown(value: string): string {
  return value.replaceAll("|", "\\|");
}

function normalizeMarkdownSpacing(lines: string[]): string[] {
  const output: string[] = [];
  for (const line of lines) {
    if (line === "" && output.at(-1) === "") {
      continue;
    }
    output.push(line);
  }
  return output;
}
