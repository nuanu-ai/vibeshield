const secretValuePatterns = [
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{16,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{12,}\b/g,
  /((?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*)(["']?)[^"'\s,}]{6,}\2/gi,
];

const redacted = "[REDACTED]";

export function redactString(value: string, explicitSecrets: string[] = []): string {
  let output = value;

  for (const secret of explicitSecrets) {
    if (secret.trim() !== "") {
      output = output.split(secret).join(redacted);
    }
  }

  for (const pattern of secretValuePatterns) {
    output = output.replace(pattern, (_match, prefix?: string) => {
      if (typeof prefix === "string" && prefix !== "") {
        return `${prefix}${redacted}`;
      }
      return redacted;
    });
  }

  return output;
}

export function redactDeep<T>(value: T, explicitSecrets: string[] = []): T {
  if (typeof value === "string") {
    return redactString(value, explicitSecrets) as T;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactDeep(item, explicitSecrets)) as T;
  }

  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value).map(([key, entryValue]) => [
      key,
      redactDeep(entryValue, explicitSecrets),
    ]);
    return Object.fromEntries(entries) as T;
  }

  return value;
}

export function containsSecretLikeValue(value: unknown, explicitSecrets: string[] = []): boolean {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (text === undefined) {
    return false;
  }

  for (const secret of explicitSecrets) {
    if (secret.trim() !== "" && text.includes(secret)) {
      return true;
    }
  }

  return redactString(text, explicitSecrets) !== text;
}
