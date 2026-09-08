# Private web interface

The three server-rendered pages submit a public GitHub repository, show actual
scan stages, and hand back a short list of jobs to do. Real-engine acceptance
uses the pinned image; an external browser check completes delivery acceptance.

The report groups published issues by the fix they share, because a reader acts
on changes rather than on alerts: issues with the same remediation key become one
job carrying every location and every piece of evidence. The first five jobs are
open and the rest are folded onto the same page with their count. No job is ever
dropped to meet a presentation limit.

The open page carries the first thing to do, then each job's plain-language
title, where it is, why it matters, what to change, how to check it, and a prompt
built from that job's own evidence. Scanner names, versions, rule and advisory
identifiers, coverage states, the commit and the image digest sit inside
disclosures. Coverage is stated separately from findings: a report can hold real
findings and incomplete checks at once.

## Run

```sh
pnpm install
pnpm toolchain:prepare
pnpm build
pnpm start
# development: pnpm dev
```

The default address is `http://127.0.0.1:3000`. `HOST` accepts an IP address or
`localhost`; `PORT` is 1–65535. A private-network bind is an explicit operator
choice. Host headers must name loopback or the actual receiving interface, with
the server's port. Arbitrary DNS aliases and forwarded Host/Origin headers are
not trusted. Browser submissions require an exact same-origin Origin header.
IPv6 literals are compared canonically. On a dual-stack `HOST=::` bind,
IPv4-mapped receiving addresses also accept their equivalent dotted IPv4 Host.
This address equivalence does not make different browser origins interchangeable.
There is no application authentication or public multi-user hosting in this slice.

The image tag is `vibeshield-toolchain:sha256-<content hash>`, derived from every
toolchain build-input path, executable mode and content hash. Re-run preparation
after any toolchain change. An explicit `VIBESHIELD_TOOLCHAIN_TAG` must match that
identity; there is no `latest` alias. Preparation verifies installed engine/base
versions, package inventory, licensed rule/check files and service scripts before
loading the image. `toolchain/versions.json` records exact upstream versions,
architecture-specific artifact digests and license sources. `VIBESHIELD_OWNER_DIR` optionally sets the absolute
private ownership-marker directory; its default is
`~/.local/state/vibeshield/runtime-ownership`. Markers contain no repository data.
Startup reconciles owned resources before listening. Shutdown closes admission,
aborts the active job, waits for verified cleanup, and exits nonzero if cleanup
cannot be confirmed. Normal job completion uses only its executor's cleanup.
There is no HTTP cleanup or administrative retry endpoint.

When cleanup cannot be verified, the report that scan already produced is still
served: withholding it does not remove the leaked sandbox, and admission stays
closed either way. Background maintenance attempts remain bounded so the process
can go idle. A refused submission starts one further attempt in the background
and is still answered 409, which is how a healed environment reopens admission
without an operator restart. The attempt is never awaited inside the response.

## HTTP and browser behavior

The routes are `GET /`, `POST /scans`, `GET /scans/:id`,
`GET /scans/:id/status`, `GET /scans/:id/report`, and the two assets
`GET /assets/app.js` and `GET /assets/app.css`. POST uses one URL-encoded
`repository` field with an 8 KiB limit on encoded bytes. Successful submissions
redirect with 303; invalid input, busy state, oversized bodies, unavailable
results and unsupported methods use 400, 409, 413, 404 and 405 respectively.
Encoded/ambiguous route paths are not normalized into accepted routes.

Status returns only the public job state, stages, public error and report
availability. It never returns report contents. A scan that ends without a report
carries a failure code — unreachable repository, snapshot over the limit,
exhausted deadline, unavailable environment, pending cleanup, or an internal
fault — and the page turns that code into one sentence with something to act on.
The precise internal reason stays in the operator diagnostic and is narrower than
what the reader is shown. A stage row reports what its check found rather than
repeating its own status word. All responses disable caching,
disable MIME sniffing and use a CSP allowing external same-origin assets.
No CORS policy is enabled. All report strings are escaped; browser updates use
`textContent`. Only progress pages poll, two seconds after the prior request
finishes. Reconnect retries status retrieval. Copy reads the displayed prompt;
when clipboard access fails the text is selected for manual copying.

## Operator diagnostics

The production server writes one JSON line to stderr for each non-waiting stage
transition and one terminal `scan_finished` event after cleanup is resolved.
Pending cleanup retries remain nonterminal and emit their own cleanup
transitions. Events contain a timestamp, scan id, stage, status and, for
failures, a bounded reason such as `timeout`, `file_limit`, `git_failed`,
`invalid_snapshot`, `sandbox_failed` or `cancelled`. A clone is classified as a
file-limit failure only when its bounded Git failure signature is accompanied by
a pack file at the enforced 64 MiB ceiling. Repository URLs and raw sandbox, Git
and scanner output are not logged. Browser status and reports remain the
sanitized user-facing contract.

## Verification

```sh
pnpm exec vitest run tests/product/web-server.test.ts tests/product/web-pages.test.ts tests/product/web-assets.test.ts
pnpm typecheck
pnpm lint
pnpm build
pnpm test:live
```

These checks exercise real HTTP routing, jobs, execution, scanner normalization,
report rendering, and the shipped browser script. The sandbox boundary supplies
controlled raw outputs. Script tests use a minimal DOM boundary; external browser
acceptance verifies actual rendering, navigation, selection and clipboard access.
No Playwright package or browser suite is installed in the repository.

`pnpm check` runs lint, typecheck, fast tests and the build. `pnpm test:live` is a
separate mandatory serial check: missing runtime, image, binary, rule or version
prerequisites fail. It runs all five actual engines on guest-owned vulnerable,
fixed, clean and malformed controls, checks historical-secret redaction and
lockfile versions, and submits a public URL through the real web/executor/runtime
composition. Scanner JSON is limited to 10 MiB; overflow fails the check. Timeout
and cleanup checks verify that task-owned process trees and VMs do not remain.
The frozen image's Bash wrapper applies the same byte ceiling to direct files
and streamed output; a complete 10 MiB control must succeed.

The public target defaults to `https://github.com/juice-shop/juice-shop`;
`VIBESHIELD_ACCEPTANCE_REPO` accepts an explicitly selected public alternative.
The resulting commit, findings, actual coverage, warnings and available advisory
freshness are written under ignored `artifacts/acceptance/`. Moving public HEAD
does not have a fixed expected issue count. A target exceeding the acquisition
limits fails truthfully; preserve its evidence before running a smaller target.
For an explicit smaller-target run:

```sh
VIBESHIELD_ACCEPTANCE_REPO=https://github.com/expressjs/express pnpm test:live
```

Fixture success establishes only those examples, not general detection accuracy.

The final external browser acceptance uses the production `pnpm start` flow to
submit the public URL, reload progress, reach the report and copy its displayed
prompt when there is a finding. The live command does not claim to replace that
browser check.

For that external browser check, run
`pnpm exec tsx tests/support/browser-server.ts` on `127.0.0.1:4317`.
Only this fixture supports `POST /__test/release-all` and `POST /__test/reset`;
the production composition has no test routes or runtime selector. Its seven
issues, including a hostile title, are derived through the real pipeline from
controlled scanner exports. Stop only the fixture process started for the check.
