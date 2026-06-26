export interface ScanArgs {
  readonly sourceArg: string | undefined;
  readonly deep: boolean;
  readonly modelMode: ScanModelMode;
}

export type ScanModelMode = "auto" | "off";

export function parseScanArgs(args: ReadonlyArray<string>): ScanArgs {
  let sourceArg: string | undefined;
  let deep = false;
  let modelMode: ScanModelMode = "auto";
  for (const arg of args) {
    if (arg === "--deep") {
      deep = true;
      continue;
    }
    if (arg === "--no-model") {
      modelMode = "off";
      continue;
    }
    if (arg.startsWith("-")) {
      throw new Error(`Unknown scan option: ${arg}`);
    }
    if (sourceArg !== undefined) {
      throw new Error(`Unexpected scan argument: ${arg}`);
    }
    sourceArg = arg;
  }
  return { sourceArg, deep, modelMode };
}
