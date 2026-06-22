#!/usr/bin/env node
// VibeShield CLI entry point.
//
// The deterministic scan flow is wired up incrementally. Until the scan and
// resume commands land, this is a stub so the package still builds; `scan` and
// `resume` are not available yet.

process.stderr.write(
  "vibeshield: the scan flow is not wired up yet.\n" + "Run this again once it is implemented.\n",
);
process.exitCode = 1;
