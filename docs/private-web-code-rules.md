# Private-web code scanner

The private-web scanner adapter runs OpenGrep 1.25.0 inside Microsandbox and reads
a bounded, service-owned SARIF file. The Dockerfile pins the Linux amd64 and arm64
release asset hashes. Repository code is parsed, never executed. Runtime pipeline
wiring is a separate step from this adapter.

Six existing GitLab SAST rules are frozen at
`7051ea7602a210dfb0793916afedc9a0555addb7`; the exact IDs, modes, paths, hashes,
licenses and remediation keys are in [the manifest](../toolchain/rules/manifest.json).
The applicable LGPL notices, original source attribution, root MIT license and
incorporated GPL license are retained in [the rules bundle](../toolchain/rules/NOTICE.md).

| Rule ID suffix (prefix `rules_lgpl_javascript_`) | Mode | Publication boundary |
| --- | --- | --- |
| `exec_rule-shelljs-os-command-exec` | search | Contextual ShellJS request-input pattern; no taint proof, suppressed by the flow gate. |
| `database_rule-node-sqli-injection` | search | Contextual query pattern; no taint proof, suppressed by the flow gate. |
| `traversal_rule-express-lfr` | taint | Request-to-Express-render path; upstream MEDIUM, not promoted. Does not prove a vulnerable template engine is configured. |
| `ssrf_rule-node-ssrf` | taint | A validated source-to-network-sink trace can publish at upstream HIGH severity. |
| `eval_rule-node-deserialize` | search | Unsafe API use, without request-to-sink proof; suppressed by the flow gate. |
| `jwt_rule-node-jwt-none-algorithm` | taint | Tracks jsonwebtoken module use to none-algorithm configuration, not attacker input. A validated trace can publish at upstream CRITICAL severity. |

Every ID has an explicit remediation policy and vulnerable/fixed/clean evidence.
Raw pattern matches remain inspectable findings; they are not silently upgraded
to high confidence. Bare eval is not selected or published. These tests establish
specific single-file API shapes, not general family, arbitrary Node API, or
cross-file coverage. The upstream SSRF sanitizers also encode broad allowlist
patterns; passing a fixed fixture is not proof that every validation scheme is safe.

The service chooses the rules, supplies empty service-owned settings and ignore
files through the pinned frontend's configuration variables, and uses
`--x-ignore-semgrepignore-files`, `--no-git-ignore`, and `--disable-nosem`.
Repository `.semgrepignore`, `.gitignore`, rule configuration and
inline `nosemgrep` comments cannot disable selected checks. The scanner permits
files up to the acquisition limit of 5 MiB. Parse/configuration warnings and
missing current locations or required traces degrade coverage; nonzero exits,
invalid SARIF and invalid bounded exports fail it. Source snippets, result
messages, fingerprints and raw diagnostics stay inside the disposable sandbox.
Reports retain static rule metadata and validated file/line flow coordinates.
Security severity comes from rule metadata, never merely SARIF `error` level.

To reproduce the source bundle, fetch the exact commit into a temporary Git
checkout, download `https://www.gnu.org/licenses/gpl-3.0.txt` to `gpl-3.0.txt` at its
root, then run `pnpm exec tsx scripts/prepare-rules.ts /path/to/checkout`.
The script verifies the GPL file's fixed SHA-256 and reads rule/fixture/license
bytes with `git show` at the frozen revision, ignoring worktree edits.
Run `pnpm exec tsx scripts/prepare-rules.ts --verify` to recheck integrity.

Verification commands:

```bash
pnpm exec vitest run tests/scanners/opengrep.test.ts tests/product/report.test.ts
VIBESHIELD_LIVE_OPENGREP=1 pnpm exec vitest run tests/scanners/opengrep.smoke.test.ts
```

OpenGrep extracts a 162 MB engine into its home cache on first use. Image building
prepares a dedicated service home before the runtime file-size limit applies.
The live test reuses the identical image-owned extracted cache through a symlink
inside the disposable VM; it does not relax the file-size limit.

The live test injects the exact guest files/rules into the existing image, checks
the engine version, runs the upstream annotation tests, and scans the synthetic
vulnerable/fixed/clean files. It destroys its owned sandbox and verifies absence,
including failure branches. A normal runtime deployment requires rebuilding the
toolchain image with these files; the live test does not replace that image.
