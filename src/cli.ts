#!/usr/bin/env node
import "dotenv/config";
import { runCli } from "./cli/run-cli.js";

const exitCode = await runCli(process.argv.slice(2), {
  stderr: process.stderr,
  stdout: process.stdout,
});

process.exitCode = exitCode;
