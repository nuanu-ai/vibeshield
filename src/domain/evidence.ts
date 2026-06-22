/**
 * The scanner output layer: raw stays inspectable, findings stay clean.
 *
 * `RedactedRawArtifact` preserves the tool's own output format with secret
 * values masked and nothing else changed. It is the proof a real tool ran.
 * `Evidence` is the normalized, still-redacted pointer back into that output.
 */

export interface RedactedRawArtifact {
  /** Blob sha256 of the redacted raw output stored in the artifact store. */
  readonly blobSha256: string;
  /** Which tool produced this output. */
  readonly tool: string;
  /** Original output format preserved by the tool (e.g. "gitleaks-json"). */
  readonly format: string;
  readonly bytes: number;
  /** Whether secret values were masked before storing. Always true in practice. */
  readonly redacted: boolean;
}

export interface Evidence {
  readonly id: string;
  readonly rawArtifactBlobSha256: string;
  /** POSIX-relative path inside the repo, validated against the manifest. */
  readonly filePath: string;
  readonly startLine: number;
  readonly endLine: number;
  /** Redacted snippet (secret values masked). */
  readonly snippet: string;
  readonly snippetHash: string;
  readonly tool: string;
}
