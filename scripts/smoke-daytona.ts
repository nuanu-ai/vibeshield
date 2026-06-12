import "dotenv/config";
import { runScan } from "../src/run/run-scan.js";

const requiredEnvVars = ["DAYTONA_API_KEY", "OPENROUTER_API_KEY"] as const;
const missingEnvVars = requiredEnvVars.filter((name) => {
  const value = process.env[name];
  return value === undefined || value.trim() === "";
});

if (missingEnvVars.length > 0) {
  console.error(
    `Skipping live Daytona smoke scan. Missing env vars: ${missingEnvVars.join(", ")}.`,
  );
  console.error(
    "Set DAYTONA_API_KEY and OPENROUTER_API_KEY, then rerun: pnpm smoke:daytona https://github.com/octocat/Hello-World",
  );
  console.error("DAYTONA_API_URL and DAYTONA_TARGET are optional overrides.");
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
