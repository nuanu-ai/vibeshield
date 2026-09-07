import { afterEach, beforeEach, expect, it } from "vitest";
import { createBrowserFixture } from "../support/browser-server.js";

let app: ReturnType<typeof createBrowserFixture>;
let base: string;
beforeEach(async () => {
  app = createBrowserFixture();
  await new Promise<void>((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
});
afterEach(async () => {
  await app.shutdown();
  expect(app.sandbox.sessions.size).toBe(0);
  expect(app.clock.pending()).toBe(0);
});
function control(name: string, data?: unknown) {
  return fetch(`${base}/__test/${name}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  });
}
async function start() {
  const response = await fetch(`${base}/scans`, {
    method: "POST",
    headers: { origin: base, "content-type": "application/x-www-form-urlencoded" },
    body: "repository=https://github.com/owner/repo",
    redirect: "manual",
  });
  expect(response.status).toBe(303);
  return response.headers.get("location") as string;
}
async function completed(path: string) {
  await expect
    .poll(
      async () =>
        ((await (await fetch(`${base}${path}/status`)).json()) as { reportReady: boolean })
          .reportReady,
    )
    .toBe(true);
}

// Exercise the clock control by its product result, not the helper's return value.
it("advances a real completed report to expiry through the test-only clock control", async () => {
  const path = await start();
  expect((await control("release-all")).status).toBe(200);
  await completed(path);
  expect((await control("advance", { ms: 3_600_000 })).status).toBe(200);
  const expired = await fetch(base + path);
  expect(expired.status).toBe(404);
  expect(await expired.text()).toContain("This result is no longer available");
});

it("fails the selected scanner while other pipeline issues remain available", async () => {
  const path = await start();
  expect((await control("fail", { scanner: "osv" })).status).toBe(200);
  await control("release-all");
  await completed(path);
  const html = await (await fetch(`${base}${path}/report`)).text();
  expect(html).toContain("Exposed credential");
  expect(html).toContain("Scan incomplete");
  expect(html).not.toContain("Known vulnerable");
});

it.each([
  ["restart", "completed"],
  ["restart", "running"],
  ["reset", "running"],
])("%s loses old %s URLs, cleans resources, and admits a fresh scan", async (action, state) => {
  const path = await start();
  const previous = app.sandbox;
  const clock = app.clock;
  await expect.poll(() => previous.started.length).toBe(1);
  if (state === "completed") {
    await control("release-all");
    await completed(path);
  }
  expect((await control(action)).status).toBe(200);
  for (const suffix of ["", "/status", "/report"]) {
    const response = await fetch(base + path + suffix);
    expect(response.status).toBe(404);
    expect(await response.text()).toContain('href="/"');
  }
  expect(previous.sessions.size).toBe(0);
  expect(clock.pending()).toBe(0);
  const fresh = await start();
  expect(fresh).not.toBe(path);
  await control("release-all");
  await completed(fresh);
});
