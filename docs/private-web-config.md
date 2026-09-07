# Private web configuration checks

The new `scanTrivy(ScannerContext)` adapter runs Trivy configuration analysis in
Microsandbox. It is separate from the legacy CLI until the web executor is wired.
It does not install packages, execute target code, pull container images, or run a
dependency vulnerability scan.

The reviewed publication rule is **KSV-0017**, `builtin.kubernetes.KSV017`, observed
as HIGH by the pinned engine on a Kubernetes Pod with
`containers[].securityContext.privileged: true`. The
[vulnerable fixture](../tests/fixtures/scanners/config/vulnerable.yaml) reports the
container at lines 15–29. Its [restricted counterpart](../tests/fixtures/scanners/config/fixed.yaml)
sets privilege to false, disables escalation, drops capabilities, uses a non-root
UID/GID and the default seccomp profile. This pair establishes this check on these
examples; it does not establish broad Kubernetes or IaC audit coverage.

Other Trivy rules are not published. Terraform, Dockerfiles, and unrecognized
YAML/JSON candidates remain explicit coverage limitations. A recognized
Kubernetes result must include PASS or FAIL evidence for the selected ID before
that file counts as checked. A missing result cannot become a clean scan.
Package metadata and the service's scanner settings filenames are not IaC inputs.

## Frozen engine and checks

[The image recipe](../toolchain/Dockerfile) installs official
[Trivy 0.72.0](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0) using
upstream SHA-256 hashes for both Linux architectures. It extracts the engine's
Apache-2.0 LICENSE into the image. The separately downloaded checks bundle is
**2.2.0**, revision `d7c9302130a9b7e614a5c5d32854f6a08b4bc52e`, from
[trivy-checks](https://github.com/aquasecurity/trivy-checks/tree/d7c9302130a9b7e614a5c5d32854f6a08b4bc52e).
That revision's [license](../toolchain/licenses/trivy-checks.LICENSE) is MIT;
it is retained in the image as CHECKS-LICENSE.

The [manifest](../toolchain/trivy-manifest.json) records the immutable OCI digest,
archive digest, and extracted content hash. The guest verifies all 641 files,
ownership, absence of symlinks, bundle schema, and engine version before invoking
Trivy. Missing or altered checks fail; Trivy's embedded fallback is not accepted.
The extracted-tree SHA-256 hashes the sorted repository-relative paths, each
followed by NUL, the lowercase SHA-256 of its file bytes, and LF.

The run uses these pinned-release flags:

```text
trivy config --config=/opt/vibeshield/trivy.yaml
  --cache-dir=/opt/vibeshield/trivy/cache
  --ignorefile=/opt/vibeshield/empty.ignore --format=json
  --output=/work/.vibeshield/trivy-raw.json
  --skip-check-update --skip-version-check --disable-telemetry
  --include-non-failures --misconfig-scanners=kubernetes
  --rego-error-limit=0 --exit-code=0 /work/snapshot
```

These flags were checked against 0.72.0's help and exercised with the actual
engine. Exit zero allows findings; operational errors remain nonzero. The
service uses an empty config/ignore and a clean environment. Repository
`trivy.yaml` and `.trivyignore` cannot suppress the selected check. No rules or
databases are downloaded during scanning.

Frozen rules are not an assertion of latest upstream coverage. The report states
the exact revision and that no update check occurred. A review older than 30 days
(or a clock before the review date) degrades bundle coverage while preserving
observed findings. Missing or different bundle metadata fails the scan.

The guest retains bounded raw output and diagnostics locally. Only the sanitized
JSON file crosses the sandbox boundary: rule metadata and coordinates remain;
target messages, code snippets, resource names, and diagnostics are omitted.
Warnings become a boolean coverage limitation. The shared exporter validates a
regular service-owned file, safe path, strict JSON/UTF-8, and an 8 MiB maximum.

## Checks

```sh
pnpm exec vitest run tests/scanners/trivy.test.ts tests/product/report.test.ts
VIBESHIELD_LIVE_TRIVY=1 pnpm exec vitest run tests/scanners/trivy.smoke.test.ts
```

The live test normally requires the installed image layout. Before the persistent
image rebuild, explicit development setup is available with
`VIBESHIELD_TRIVY_TEST_LAYOUT=inject` and `VIBESHIELD_TRIVY_TEST_BUNDLE` pointing to
the exact official bundle archive. This only prepares a disposable test VM;
production has no injection or host-scanner path. The acceptance checks real
vulnerable/fixed reports, hostile repository config/ignore files, malformed YAML,
exit meanings, bundle tampering/missing files, and verified VM removal.

[The sanitized JSON fixture](../tests/fixtures/scanners/config/trivy.json) was
captured from 0.72.0 with the frozen bundle. It retains the selected FAIL and PASS
rows only; dynamic timestamps, target snippets/messages, and unrelated rules were
removed. Live acceptance compares those rows to a fresh actual-engine result.
