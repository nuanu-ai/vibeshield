#!/usr/bin/env node
// VibeShield CLI entry point.
//
// Stage 1 rewire in progress: the old MVP entry (`./cli/run-cli.js`) was
// removed. The new deterministic scan flow is wired up incrementally by the
// Gate 1 implementation tasks. Until then this is a stub so the package still
// builds; `scan`/`resume` are not available yet.

process.stderr.write(
  "vibeshield: stage 1 scan flow is not wired up yet.\n" +
    "The deterministic Quick Scan is being built; run this again once Gate 1 lands.\n",
);
process.exitCode = 1;
