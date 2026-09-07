# Private web workflow checks

The private web scanner adapter uses zizmor 1.30.0 offline in Microsandbox.
It publishes high-severity, high-confidence `template-injection` findings with
primary workflow locations and the audit's remediation reference. The reviewed
fixture interpolates a pull request title into `run`; passing it through an
environment variable and quoting the shell expansion removes that finding.

The engine's [immutable release](https://github.com/zizmorcore/zizmor/releases/tag/v1.30.0)
is pinned to commit `fb814d6687450fc8e0b0fba8d958b1ac40c0647f`.
The Dockerfile verifies official Linux archive digests for amd64 and arm64 and
includes the upstream MIT license. The service config enumerates the release's
41 audits and disables all except `template-injection`.

The wrapper supplies the image-owned config and `--no-ignores`, selects explicit
workflow files from the Git-filtered snapshot, and uses `--strict-collection`.
Repository config, inline ignore annotations, and `.gitignore` cannot suppress
the selected workflow checks. It never executes workflow steps, follows action
references, installs dependencies, or applies zizmor auto-fixes.

zizmor JSON goes directly to a guest file descriptor. The service exports only
identifiers, determinations, and primary source coordinates after bounded file
validation. Raw workflow snippets, annotations, fix payloads, and diagnostics
stay in the disposable guest. Malformed YAML, tool errors, missing evidence,
unsafe paths, and oversized exports cannot become a successful empty check.
Engine warnings reduce coverage.

Every emitted record is checked before publication filtering: it must have an
audit ID, audit reference, primary location, and supported severity/confidence
values. A malformed record fails the entire workflow result, including a mix of
valid and malformed records. Well-formed unselected audit records are filtered
without failing coverage.

## Coverage limits

Only root `.github/workflows/*.yml` and `*.yaml` files are included. Composite
actions, reusable-workflow resolution, and external action contents are outside
this slice. Routine hash pinning and generic permission/trigger advice are not
standalone important findings.

The pinned [`dangerous-triggers` implementation](https://github.com/zizmorcore/zizmor/blob/fb814d6687450fc8e0b0fba8d958b1ac40c0647f/crates/zizmor/src/audit/dangerous_triggers.rs)
emits a high-severity, medium-confidence finding for `pull_request_target` or
`workflow_run` at the workflow's `on` coordinate. It does not establish an
untrusted checkout followed by execution with privileges. No such detection is
claimed or published: this requested combination remains an explicit skipped
coverage area. Adding it needs an established analyzer that supplies that
evidence, or a separately reviewed detector.

`impostor-commit`, `ref-confusion`, `stale-action-refs`, `ref-version-mismatch`,
and `known-vulnerable-actions` are unavailable offline. These skips remain
visible even when the selected local audit succeeds or finds an issue.

## Verification

Fast normalization and publication tests:

```sh
pnpm exec vitest run tests/scanners/zizmor.test.ts tests/product/report.test.ts
```

Actual installed-image acceptance (missing prerequisites fail when enabled):

```sh
VIBESHIELD_LIVE_ZIZMOR=1 pnpm exec vitest run tests/scanners/zizmor.smoke.test.ts
```

During image development only, the same test accepts an explicit
`VIBESHIELD_ZIZMOR_TEST_LAYOUT=inject` plus `VIBESHIELD_ZIZMOR_TEST_ARCHIVE`
pointing to the official digest-verified archive. It installs the pinned engine
and current service files inside a disposable VM, verifies their bytes, and
destroys the VM afterward. This does not rebuild the persistent full toolchain
image or constitute final product acceptance.
