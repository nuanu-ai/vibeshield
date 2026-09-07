# Private-web dependency scanner

The adapter runs official OSV-Scanner **2.3.8** inside Microsandbox. Its upstream
source is [commit 408fcd6f8707999a29e7ba45e15809764cf24f67](https://github.com/google/osv-scanner/tree/408fcd6f8707999a29e7ba45e15809764cf24f67),
and the Dockerfile verifies the published Linux amd64/arm64 release hashes.
The existing pipeline is replaced and wired separately; this document describes
the new `scanOsv(ScannerContext)` adapter.

The selected extractors recognize `package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`, and `bun.lock`. Each recognized path in the acquisition snapshot gets
its own coverage entry. A checked entry requires actual package inventory from
that path, including clean packages via `--all-packages`. Missing inventory is
degraded: an empty lockfile cannot be distinguished reliably from an omitted
parse in official JSON. Other detected lockfiles and manifests without a supported
lockfile are explicit limitations. This policy does not claim other ecosystems.

A nested `package.json` can share a scanned workspace-root lockfile only when
its exact snapshot path matches that root's workspace declaration. npm, Yarn,
and Bun read `package.json` workspaces; pnpm requires `pnpm-workspace.yaml`.
The guest reads only acquisition-listed root configs with bounded, no-symlink
file access and exports only `{manifest, lockfile}` membership pairs. The host
cross-checks both paths against the snapshot and requires actual non-degraded
OSV inventory for the root lockfile. An ancestor lockfile or a declaration alone
does not cover a child; omitted lockfiles and independent nested projects remain
explicit coverage gaps. Canonical finding/provenance contracts are unchanged.

Membership recognition is intentionally conservative: exact relative directory
paths and whole-segment `*`/`**` globs, with exclusions taking precedence. JSON
workspace arrays (including the `packages` object form) and a standalone pnpm
`packages:` block list are recognized. Complex globs, re-inclusion overrides,
inline/anchored/merged/multi-document YAML and YAML containing other configuration
sections are not interpreted; unmatched manifests retain missing-lockfile
coverage. No package-manager command runs and no dependency range is resolved.
See [Yarn workspace declarations](https://yarnpkg.com/features/workspaces),
[npm workspace mapping](https://github.com/npm/map-workspaces/blob/main/lib/index.js),
[pnpm workspace configuration](https://pnpm.io/pnpm-workspace_yaml), and
[Bun workspaces](https://bun.com/docs/pm/workspaces).

The service selects only the four JavaScript lockfile extractors, supplies an
empty `/opt/vibeshield/osv.toml`, and uses `--no-ignore`, `--all-vulns`,
`--no-call-analysis=all`, and `--no-resolve`. The last two flags are essential:
Go call analysis is enabled by default upstream, and manifest resolution can
produce versions that were never installed. VibeShield never installs packages
or executes target scripts. Repository `osv-scanner.toml`, `.gitignore`, custom
OSV JSON and package scripts cannot select or suppress this policy.
See the pinned [source scanning documentation](https://github.com/google/osv-scanner/blob/v2.3.8/docs/scan-source.md)
and [configuration contract](https://github.com/google/osv-scanner/blob/v2.3.8/docs/configuration.md).

The command writes JSON to a service-owned file. The guest bounds and sanitizes
it before export; scanner stdout is discarded. Warning/error diagnostics at
`--verbosity=warn` become a boolean coverage limitation and their text stays in
the guest. In this release, exit `1` can take precedence over logged parse errors,
so its exit code alone cannot establish complete coverage.

| Official exit | Meaning and adapter behavior |
| --- | --- |
| 0 | Completed without vulnerabilities; validate package inventory. |
| 1 | Vulnerabilities found; validate records and preserve diagnostic coverage loss. |
| 127 | Generic error (also returned by `--help`); fail coverage. |
| 128 | No packages found; fail coverage. |
| 129 | Advisory API failure; fail coverage. |
| 130 | Invalid configuration; fail coverage. |
| 124 | Service timeout; fail coverage. |

Normalized findings retain ecosystem, package, exact lockfile version, manifest,
scope when supplied, advisory and group aliases, and fixed versions for the
matching package. Unspecified scope stays unknown. Severity uses advisory
`database_specific.severity` (`MODERATE` maps to medium). Missing/unrecognized
severity stays unknown and degrades coverage; there is no inferred critical
severity or local CVSS implementation. Fixed versions are advisory facts, not
proof that an arbitrary upgrade resolves every issue or preserves compatibility.

The OSV wildcard publication policy retains high/critical advisories with complete
dependency evidence. Medium/low/unknown advisories remain inspectable findings.
Equivalent aliases group only within the same package version and manifest.
Development dependencies are eligible because build/CI exposure can matter;
these scans do not establish runtime reachability.

`readOsvAdvisoryData(session)` reads the same bounded export after a successful
scan for the canonical report's `provenance.advisoryData`. It supplies source
`OSV`, the actual completed retrieval timestamp, and `stale: false`. The API does
not supply a database revision, so `revision` is absent. Failures/diagnostics
return no freshness claim; their coverage remains incomplete. The canonical
`Finding` and `ScanResult` contracts are unchanged.

Verification:

```bash
pnpm exec vitest run tests/scanners/osv.test.ts tests/product/report.test.ts
VIBESHIELD_LIVE_OSV=1 pnpm exec vitest run tests/scanners/osv.smoke.test.ts
```

The live test defaults to validating installed image artifacts. Before the
persistent image is prepared, explicit `VIBESHIELD_OSV_BINARY=/absolute/path/to/osv-scanner_linux_arm64`
(or the amd64 binary) enables installation of missing artifacts in the disposable
test VM. It verifies the upstream binary digest and the current service-script
bytes; existing stale image files fail validation. This development mode does
not rebuild the persistent image or change scanner resource limits.

The checked-in fixtures hold the same `^4.17.0` manifest range but resolve lodash
to vulnerable `4.17.20` and fixed `4.18.0`. On 2026-09-07, the live adapter found
five advisory records in the vulnerable fixture and none in the fixed fixture.
Three medium records were suppressed; the two high records share aliases and
became one public issue. The live test also verifies repository ignore resistance,
malformed-lockfile coverage, no package-script marker, and VM cleanup. These
fixtures establish those examples, not general dependency detection accuracy.
The live Yarn fixture also proves shared-root coverage for a declared
`packages/app` workspace and missing-lockfile coverage for a separate
`independent` package despite the same scanned ancestor lockfile.
