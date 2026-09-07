# Sandbox lifecycle and limits

Every production sandbox mounts `/work` as a 2 GiB tmpfs with `nosuid` and
`nodev`. Microsandbox 0.5.7 was verified live on macOS: writes filled exactly
2,147,483,648 bytes and the next write failed with `ENOSPC`. This mount is the
hard workspace bound. It does not limit the whole guest root filesystem.

Each command runs through the service-owned `toolchain/run-check.mjs`, uploaded
with its JSON configuration outside the repository under `/run`. The wrapper
starts a separate process group, applies an inherited per-file size limit, and
polls allocated workspace bytes every 250 ms without following repository
symlinks. The watchdog is an additional stop mechanism, not a hard quota. The
measured hard-mount overshoot is zero; no standalone watchdog overshoot guarantee
is claimed. The per-file ceiling is at most 64 MiB (32 MiB with the installed
guest shell's 512-byte `ulimit -f` units). This also bounds writes between polls.

Stdout and stderr each retain a 64 KiB diagnostic tail. Callers needing complete
scanner JSON must use an explicit output file under `/work`, with
`SandboxExecOptions.stdoutPath` for stdout-producing scanners. That output file
is exclusive-created, never follows a symlink, and is capped at 64 MiB. Scanner
commands producing their own output files inherit the per-file limit too.
Commands time out after ten minutes unless given a shorter positive timeout.

Cancellation signals the active wrapper and destroys its VM. A cancelled create
waits for the SDK to finish creation and removes the returned sandbox before
settling. The owning SDK handle is retained for shutdown; a separate database
handle cannot reliably close an active owning connection in SDK 0.5.7. Cleanup
uses bounded retries and CLI timeouts, preserves failures, and succeeds only
after the SDK's resource list confirms absence. A failed cleanup must keep job
admission closed until cleanup is retried successfully.

Private 0600 ownership markers contain only a sandbox name and random ownership
token. The default owner directory is
`~/.local/state/vibeshield/runtime-ownership`; callers may provide a canonical
absolute `ownerDir` with mode 0700 owned by the service user. Creation records a
marker before starting the VM and adds the same token as the VM's
`vibeshield.owner` label. Startup reconciliation removes only matching labelled
resources, skips symlink markers and mismatched ownership, and removes a marker
only after absence is confirmed. Existing VM names are never replaced.

The live timeout test confirmed that the command parent disappeared and its
sleep child was terminated. This guest image can retain the child as a zombie
until VM removal; it is not executing. Cancellation and final removal confirmed
the entire disposable VM absent. The broader final scanner acceptance task
remains separate from these lifecycle probes.

The private web scan coordinator in `src/web/jobs.ts` reserves one slot before
starting asynchronous work. Its executor acquires one snapshot, runs Gitleaks,
OpenGrep, OSV, Trivy and zizmor sequentially, and builds the deterministic report.
Scanner failures preserve the other engines' findings and appear in coverage;
failure before a validated snapshot produces a failed job without a report.

The coordinator starts a cumulative ten-minute deadline using its injected
`Clock`. An internal signal-to-deadline registration in `src/web/clock.ts` lets
`createExecutor(runtime, provenance)` recheck the same wall-clock deadline before
and after sandbox I/O, including export reads. Scheduled abort also works for
executors that emit no progress. A standalone executor registers its own
`systemClock` deadline. The owner disposes timers and registration when execution
settles. Deadline or shutdown cancellation destroys the active sandbox; outstanding
creation must settle before cleanup can be verified. Checks that did not complete
remain explicit failures beside any already completed findings.

Each engine also has one cumulative two-minute budget, including all of its
commands and export reads. Gitleaks current and history checks share this budget.
The engine deadline is capped by the remaining overall deadline. Every guest
command receives the smaller of its existing timeout and the engine's remaining
time; the executor waits for the guest wrapper to terminate that process group
before continuing in the same sandbox. Engine cancellation does not propagate
to the overall job. Clock checks around each operation prevent further scanner
work after the deadline even when timer delivery is delayed. Child timers,
listeners and deadline registrations are removed after each engine.

The engine signal is not sent to the runtime's cancellation path, which removes
the whole VM. A stalled SDK transport or export read therefore remains governed
by the overall abort/removal deadline; no next scanner starts while its operation
is unsettled. This boundary preserves the existing runtime cancellation contract.

Executor resolution follows verified cleanup. When cleanup fails, the coordinator
keeps `cleanup-failed` visible and its slot reserved. A normalized report, if one
was prepared, stays private until the operator calls `retryCleanup()` and its
injected ownership-aware cleanup succeeds. Failed creation never authorizes
deleting an unrelated resource by name. Shutdown closes admission, aborts active
work, waits for cleanup, cancels retention timers and rejects cleanup failures.

Jobs live only in memory. Completed reports expire exactly one hour after verified
completion; the 21st report evicts the oldest completed report. Failed jobs also
expire after one hour. A new store does not restore old URLs. Cleanup failures
have no expiry while their slot is reserved. Base provenance is supplied by the
composition root; only validated OSV advisory provenance is appended before
cleanup. Raw scanner output, credentials, graphs and model metadata are not stored
in jobs or reports. These modules do not use the legacy persistent scan service.
