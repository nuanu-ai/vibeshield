export interface ScanArgs {
  readonly sourceArg: string | undefined;
  readonly deep: boolean;
}

export function parseScanArgs(args: ReadonlyArray<string>): ScanArgs {
  let sourceArg: string | undefined;
  let deep = false;
  for (const arg of args) {
    if (arg === "--deep") {
      deep = true;
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
  return { sourceArg, deep };
}
