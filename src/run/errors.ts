import type { RunStage } from "./types.js";

export class ScanStageError extends Error {
  readonly diagnostics: string[];
  readonly stage: RunStage;
  readonly userMessage: string;

  constructor(input: {
    cause?: unknown;
    diagnostics?: string[];
    message: string;
    stage: RunStage;
    userMessage?: string;
  }) {
    super(input.message, input.cause === undefined ? undefined : { cause: input.cause });
    this.diagnostics = input.diagnostics ?? [];
    this.name = "ScanStageError";
    this.stage = input.stage;
    this.userMessage = input.userMessage ?? input.message;
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

export function toScanStageError(error: unknown, stage: RunStage): ScanStageError {
  if (error instanceof ScanStageError) {
    return error;
  }

  const message = errorMessage(error);
  return new ScanStageError({
    cause: error,
    message,
    stage,
    userMessage: `VibeShield stopped during ${stage}: ${message}`,
  });
}
