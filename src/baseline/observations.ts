import type { BaselineObservation, BaselineToolName } from "../artifacts/contracts.js";

const maxObservationMessageLength = 260;

export function normalizeBaselineObservations(input: {
  status: "completed" | "failed" | "skipped";
  stderr?: string;
  stdout?: string;
  tool: BaselineToolName;
}): BaselineObservation[] {
  if (input.status !== "completed") {
    return [];
  }

  switch (input.tool) {
    case "trivy":
      return normalizeTrivy(input.stdout);
    case "checkov":
      return normalizeCheckov(input.stdout);
    case "gitleaks":
      return normalizeGitleaks(input.stdout);
    case "actionlint":
      return normalizeActionlint(input.stdout, input.stderr);
    case "zizmor":
      return normalizeZizmor(input.stdout);
    case "syft":
      return [];
  }
}

function normalizeTrivy(stdout: string | undefined): BaselineObservation[] {
  const data = parseJsonObject(stdout);
  const results = Array.isArray(data?.Results) ? data.Results : [];
  const observations: BaselineObservation[] = [];

  for (const result of results) {
    const target = typeof result?.Target === "string" ? result.Target : "trivy result";

    for (const vulnerability of asArray(result?.Vulnerabilities)) {
      const id = stringValue(vulnerability?.VulnerabilityID, "unknown vulnerability");
      const pkg = stringValue(vulnerability?.PkgName, "unknown package");
      const installed = stringValue(vulnerability?.InstalledVersion, "unknown version");
      const fixed = stringValue(vulnerability?.FixedVersion, "");
      const title = stringValue(vulnerability?.Title, "");
      observations.push({
        confidence: "high",
        evidence: [target],
        kind: "dependency",
        message: compact(
          `${id} in ${pkg}@${installed}${fixed ? ` fixed in ${fixed}` : ""}${title ? `: ${title}` : ""}`,
        ),
        severity: normalizeSeverity(vulnerability?.Severity),
      });
    }

    for (const misconfiguration of asArray(result?.Misconfigurations)) {
      const causeMetadata = recordValue(misconfiguration.CauseMetadata);
      const id = stringValue(misconfiguration?.ID, "unknown misconfiguration");
      const title = stringValue(misconfiguration?.Title, "");
      const evidence = evidenceFromPathAndRange(
        stringValue(causeMetadata?.Resource, target),
        causeMetadata?.StartLine,
        causeMetadata?.EndLine,
      );
      observations.push({
        confidence: "high",
        evidence,
        kind: "iac",
        message: compact(`${id}${title ? `: ${title}` : ""}`),
        severity: normalizeSeverity(misconfiguration?.Severity),
      });
    }

    for (const secret of asArray(result?.Secrets)) {
      const rule = stringValue(secret?.RuleID, "secret detected");
      observations.push({
        confidence: "high",
        evidence: evidenceFromPathAndRange(target, secret?.StartLine, secret?.EndLine),
        kind: "secret",
        message: compact(rule),
        severity: normalizeSeverity(secret?.Severity, "high"),
      });
    }
  }

  return observations;
}

function normalizeCheckov(stdout: string | undefined): BaselineObservation[] {
  const data = parseJsonObject(stdout);
  const results = recordValue(data?.results);
  const failedChecks = asArray(results?.failed_checks);

  return failedChecks.map((check) => {
    const id = stringValue(check?.check_id, "unknown check");
    const name = stringValue(check?.check_name, "");
    const range = Array.isArray(check?.file_line_range) ? check.file_line_range : [];
    return {
      confidence: "high",
      evidence: evidenceFromPathAndRange(
        stringValue(check?.file_path ?? check?.repo_file_path ?? check?.file_abs_path, ""),
        range[0],
        range[1],
      ),
      kind: "iac",
      message: compact(`${id}${name ? `: ${name}` : ""}`),
      severity: normalizeSeverity(check?.severity),
    };
  });
}

function normalizeGitleaks(stdout: string | undefined): BaselineObservation[] {
  const data = parseJson(stdout);
  const dataRecord = recordValue(data);
  const findings = Array.isArray(data)
    ? data.filter(isRecord)
    : asArray(dataRecord?.findings ?? dataRecord?.Findings);

  return findings.map((finding) => {
    const rule = stringValue(finding?.RuleID ?? finding?.ruleID, "secret detected");
    const description = stringValue(finding?.Description ?? finding?.description, "");
    return {
      confidence: "high",
      evidence: evidenceFromPathAndRange(
        stringValue(finding?.File ?? finding?.file, ""),
        finding?.StartLine ?? finding?.startLine,
        finding?.EndLine ?? finding?.endLine,
      ),
      kind: "secret",
      message: compact(`${rule}${description ? `: ${description}` : ""}`),
      severity: "high",
    };
  });
}

function normalizeActionlint(
  stdout: string | undefined,
  stderr: string | undefined,
): BaselineObservation[] {
  const text = `${stdout ?? ""}\n${stderr ?? ""}`.trim();
  if (!text) {
    return [];
  }

  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      const match = /^(?<path>.+?):(?<line>\d+):(?<column>\d+):\s*(?<message>.+)$/.exec(line);
      if (match?.groups === undefined) {
        return [];
      }
      const pathGroup = match.groups.path;
      const lineGroup = match.groups.line;
      const messageGroup = match.groups.message;
      if (pathGroup === undefined || lineGroup === undefined || messageGroup === undefined) {
        return [];
      }
      return [
        {
          confidence: "high" as const,
          evidence: evidenceFromPathAndRange(pathGroup, Number(lineGroup)),
          kind: "workflow" as const,
          message: compact(messageGroup),
          severity: "medium" as const,
        },
      ];
    });
}

function normalizeZizmor(stdout: string | undefined): BaselineObservation[] {
  const data = parseJson(stdout);
  const dataRecord = recordValue(data);
  const alerts = Array.isArray(data)
    ? data.filter(isRecord)
    : asArray(dataRecord?.alerts ?? dataRecord?.results);

  return alerts.flatMap((alert) => {
    if (alert === null || typeof alert !== "object") {
      return [];
    }

    const message = stringValue(
      alert.title ?? alert.message ?? alert.description ?? alert.rule ?? alert.ident,
      "",
    );
    if (!message) {
      return [];
    }

    return [
      {
        confidence: "medium" as const,
        evidence: evidenceFromZizmorAlert(alert),
        kind: "workflow" as const,
        message: compact(message),
        severity: normalizeSeverity(alert.severity, "medium"),
      },
    ];
  });
}

function evidenceFromZizmorAlert(alert: Record<string, unknown>): string[] {
  const locations = asArray(alert.locations ?? alert.location);
  const evidence = locations.flatMap((location) => {
    if (location === null || typeof location !== "object") {
      return [];
    }
    const locationRecord = location as Record<string, unknown>;
    return evidenceFromPathAndRange(
      stringValue(locationRecord.path ?? locationRecord.file ?? locationRecord.filename, ""),
      locationRecord.line ?? locationRecord.start_line,
      locationRecord.end_line,
    );
  });

  return evidence.length > 0 ? evidence : [];
}

function parseJsonObject(text: string | undefined): Record<string, unknown> | null {
  const parsed = parseJson(text);
  return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : null;
}

function parseJson(text: string | undefined): unknown {
  if (text === undefined || text.trim() === "") {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function asArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function normalizeSeverity(
  value: unknown,
  fallback: BaselineObservation["severity"] = "unknown",
): BaselineObservation["severity"] {
  if (typeof value !== "string") {
    return fallback;
  }

  switch (value.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
    case "moderate":
      return "medium";
    case "low":
      return "low";
    case "info":
    case "informational":
      return "info";
    default:
      return fallback;
  }
}

function evidenceFromPathAndRange(
  pathValue: string,
  startLine?: unknown,
  endLine?: unknown,
): string[] {
  const normalizedPath = normalizePath(pathValue);
  if (!normalizedPath) {
    return [];
  }

  const start = typeof startLine === "number" && Number.isFinite(startLine) ? startLine : undefined;
  const end = typeof endLine === "number" && Number.isFinite(endLine) ? endLine : undefined;
  if (start === undefined || start <= 0) {
    return [normalizedPath];
  }
  if (end !== undefined && end > start) {
    return [`${normalizedPath}:${start}-${end}`];
  }
  return [`${normalizedPath}:${start}`];
}

function normalizePath(value: string): string {
  return value
    .replaceAll("\\", "/")
    .replace(/^\/home\/daytona\/repo\//, "")
    .replace(/^\/repo\//, "")
    .replace(/^repo\//, "")
    .replace(/^\//, "")
    .trim();
}

function compact(value: string): string {
  const singleLine = value.replace(/\s+/g, " ").trim();
  return singleLine.length > maxObservationMessageLength
    ? `${singleLine.slice(0, maxObservationMessageLength - 1)}...`
    : singleLine;
}
