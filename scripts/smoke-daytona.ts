import { runScan } from "../src/run/run-scan.js";

const requiredEnvVars = ["DAYTONA_API_KEY", "DAYTONA_API_URL", "DAYTONA_TARGET"] as const;
const missingEnvVars = requiredEnvVars.filter((name) => process.env[name] === undefined);

if (missingEnvVars.length > 0) {
  console.error(
    `Skipping live Daytona smoke scan. Missing env vars: ${missingEnvVars.join(", ")}.`,
  );
  console.error(
    "Set Daytona credentials and rerun: pnpm smoke:daytona https://github.com/octocat/Hello-World",
  );
  process.exitCode = 2;
} else {
  const repoUrl = process.argv[2] ?? "https://github.com/octocat/Hello-World";
  const result = await runScan({ repoUrlInput: repoUrl });

  if (result.exitCode === 0) {
    console.log(`Live Daytona smoke scan succeeded. Run directory: ${result.runDir}`);
  } else {
    console.error(`Live Daytona smoke scan failed: ${result.userMessage}`);
    if (result.runDir !== undefined) {
      console.error(`Run directory: ${result.runDir}`);
    }
  }

  process.exitCode = result.exitCode;
}
