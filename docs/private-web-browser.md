# Private web interface

The three server-rendered pages submit a public GitHub repository, show actual
scan stages, and display grouped findings with evidence, remediation and copyable
agent prompts. The first five issues start open; every remaining issue is on the
same page. Incomplete coverage stays visible beside findings.

This implementation is part of the private web transition. The existing CLI and
its documentation remain until the final removal task. Full real-engine browser
acceptance and a content-derived toolchain image are still required before the
web MVP is declared delivered.

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
There is no application authentication or public multi-user hosting in this slice.

`VIBESHIELD_TOOLCHAIN_TAG` selects the prepared image, defaulting to
`vibeshield-toolchain:latest`. The expected five versions and rules provenance
match the current image recipe/policies; final image verification belongs to the
separate live acceptance task. `VIBESHIELD_OWNER_DIR` optionally sets the absolute
private ownership-marker directory; its default is
`~/.local/state/vibeshield/runtime-ownership`. Markers contain no repository data.
Startup reconciles owned resources before listening. Shutdown closes admission,
aborts the active job, waits for verified cleanup, and exits nonzero if cleanup
cannot be confirmed. Normal job completion uses only its executor's cleanup.
There is no HTTP cleanup or administrative retry endpoint.

## HTTP and browser behavior

The routes are `GET /`, `POST /scans`, `GET /scans/:id`,
`GET /scans/:id/status`, `GET /scans/:id/report`, and the two assets
`GET /assets/app.js` and `GET /assets/app.css`. POST uses one URL-encoded
`repository` field with an 8 KiB limit on encoded bytes. Successful submissions
redirect with 303; invalid input, busy state, oversized bodies, unavailable
results and unsupported methods use 400, 409, 413, 404 and 405 respectively.
Encoded/ambiguous route paths are not normalized into accepted routes.

Status returns only the public job state, stages, public error and report
availability. It never returns report contents. All responses disable caching,
disable MIME sniffing and use a CSP allowing external same-origin assets.
No CORS policy is enabled. All report strings are escaped; browser updates use
`textContent`. Only progress pages poll, two seconds after the prior request
finishes. Reconnect retries status retrieval. Copy reads the displayed prompt;
when clipboard access fails the text is selected for manual copying.

## Verification

```sh
pnpm exec vitest run tests/product/web-server.test.ts tests/product/web-pages.test.ts tests/product/web-assets.test.ts
pnpm typecheck
pnpm lint
pnpm build
```

These checks exercise real HTTP routing, jobs, execution, scanner normalization,
report rendering, and the shipped browser script. The sandbox boundary supplies
controlled raw outputs. Script tests use a minimal DOM boundary; external browser
acceptance verifies actual rendering, navigation, selection and clipboard access.
No Playwright package or browser suite is installed in the repository.

For that external browser check, run
`pnpm exec tsx tests/support/browser-server.ts` on `127.0.0.1:4317`.
Only this fixture supports `POST /__test/release-all` and `POST /__test/reset`;
the production composition has no test routes or runtime selector. Its seven
issues, including a hostile title, are derived through the real pipeline from
controlled scanner exports. Stop only the fixture process started for the check.
