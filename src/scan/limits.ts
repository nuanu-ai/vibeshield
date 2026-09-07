export const LIMITS = {
  cpus: 2,
  memoryMib: 4096,
  totalMs: 600_000,
  acquisitionMs: 120_000,
  scannerMs: 120_000,
  historyCommits: 100,
  files: 50_000,
  snapshotBytes: 500 * 1024 * 1024,
  workspaceBytes: 2 * 1024 ** 3,
  reportTtlMs: 3_600_000,
  reports: 20,
  pollMs: 2_000,
} as const;
