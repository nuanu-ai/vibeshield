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
