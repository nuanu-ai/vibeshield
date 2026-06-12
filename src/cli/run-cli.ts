import { type RunScanOptions, runScan } from "../run/run-scan.js";

export interface CliWritable {
  write(chunk: string): unknown;
}

export interface CliIo {
  stderr: CliWritable;
  stdout: CliWritable;
}

export type CliDependencies = Pick<RunScanOptions, "runsRoot" | "sandboxProvider">;

const usage = `Usage:
  vibeshield scan https://github.com/owner/repo
`;

export async function runCli(
  argv: string[],
  io: CliIo,
  dependencies: CliDependencies = {},
): Promise<number> {
  const [command, repoUrl, ...rest] = argv;

  if (command !== "scan" || repoUrl === undefined || rest.length > 0) {
    io.stderr.write(usage);
    return 1;
  }

  const scanOptions: RunScanOptions = { repoUrlInput: repoUrl };
  scanOptions.onProgress = (event) => {
    io.stdout.write(`[${event.stage}] ${event.message}\n`);
  };
  if (dependencies.runsRoot !== undefined) {
    scanOptions.runsRoot = dependencies.runsRoot;
  }
  if (dependencies.sandboxProvider !== undefined) {
    scanOptions.sandboxProvider = dependencies.sandboxProvider;
  }

  const result = await runScan(scanOptions);

  if (result.exitCode === 0) {
    io.stdout.write(`Run directory: ${result.runDir}\n`);
    return 0;
  }

  io.stderr.write(`Error: ${result.userMessage}\n`);
  if (result.runDir !== undefined) {
    io.stderr.write(`Run directory: ${result.runDir}\n`);
  }
  return 1;
}
