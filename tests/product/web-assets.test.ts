import { runInNewContext } from "node:vm";
import { expect, it, vi } from "vitest";
import { browserScript } from "../../src/web/assets.js";
import { createBrowserFixture } from "../support/browser-server.js";

/** Minimal DOM boundary. Real DOM/rendering and clipboard permissions are covered
 * by external browser acceptance; here the shipped script executes unmodified. */
function browser(progress = true) {
  const listeners = new Map<string, () => Promise<void>>();
  const element = (key: string, textContent = "") => ({
    textContent,
    hidden: false,
    dataset: { stage: "acquire" },
    set innerHTML(_value: string) {
      throw new Error("Unsafe HTML update");
    },
    addEventListener: (_name: string, callback: () => Promise<void>) =>
      listeners.set(key, callback),
    focus: () => {},
  });
  const status = element("status");
  const error = element("error");
  const retry = element("retry");
  const stage = element("stage");
  const copyStatus = element("copy-status");
  const prompt = element("prompt", "  Exact <evidence> & remediation\nVerify it.\n");
  const issue = {
    querySelector: (selector: string) => (selector === "[data-prompt]" ? prompt : copyStatus),
  };
  const copy = { ...element("copy"), closest: () => issue };
  const fetch = vi.fn<(...args: unknown[]) => Promise<unknown>>();
  let selected = "";
  const clipboard = { writeText: vi.fn(async (_text: string) => {}) };
  const location = { pathname: "/scans/opaque", assign: vi.fn(), reload: vi.fn() };
  const timers = new Map<number, { callback: () => Promise<void>; ms: number }>();
  let nextId = 0;
  const document = {
    body: { hasAttribute: () => progress },
    querySelector: (selector: string) =>
      selector === "[data-status]" ? status : selector === "[data-error]" ? error : retry,
    querySelectorAll: (selector: string) =>
      selector === "[data-copy]"
        ? [copy]
        : [{ dataset: { stage: "acquire" }, querySelector: () => stage }],
    createRange: () => ({
      selectNodeContents: (node: typeof prompt) => {
        selected = node.textContent;
      },
    }),
  };
  const context = {
    document,
    fetch,
    location,
    navigator: { clipboard },
    window: { getSelection: () => ({ removeAllRanges: () => {}, addRange: () => {} }) },
    setTimeout: (callback: () => Promise<void>, ms: number) => {
      const id = nextId++;
      timers.set(id, { callback, ms });
      return id;
    },
    clearTimeout: (id: number) => timers.delete(id),
  };
  return {
    status,
    error,
    retry,
    stage,
    copyStatus,
    prompt,
    fetch,
    clipboard,
    location,
    timers,
    listeners,
    selected: () => selected,
    run: () => runInNewContext(browserScript, context),
  };
}
const state = (overrides = {}) => ({
  status: "running",
  reportReady: false,
  stages: [{ stage: "acquire", status: "running", message: "<img src=x onerror=alert(1)>" }],
  ...overrides,
});
const response = (body = state()) => ({ ok: true, status: 200, json: async () => body });
const settle = async () => {
  for (let i = 0; i < 8; i++) await Promise.resolve();
};

it("waits until status settles before scheduling 2s polling and uses textContent", async () => {
  const b = browser();
  let resolve!: (value: unknown) => void;
  b.fetch.mockReturnValue(
    new Promise((done) => {
      resolve = done;
    }),
  );
  b.run();
  expect(b.fetch).toHaveBeenCalledWith("/scans/opaque/status", { cache: "no-store" });
  expect(b.timers.size).toBe(0);
  void b.listeners.get("retry")?.();
  expect(b.fetch).toHaveBeenCalledTimes(1);
  resolve(response());
  await settle();
  expect(b.stage.textContent).toBe("<img src=x onerror=alert(1)>");
  expect([...b.timers.values()].map((timer) => timer.ms)).toEqual([2000]);
  b.fetch.mockResolvedValue(response(state({ reportReady: true, status: "completed" })));
  await [...b.timers.values()][0]?.callback();
  expect(b.location.assign).toHaveBeenCalledWith("/scans/opaque/report");
  expect(b.timers.size).toBe(0);
});
it("reconnect retries only status, while fatal jobs and unavailable results stop polling", async () => {
  const b = browser();
  b.fetch.mockRejectedValue(new Error("offline"));
  b.run();
  await settle();
  expect(b.error.textContent).toContain("lost the connection");
  expect(b.retry.hidden).toBe(false);
  expect(b.timers.size).toBe(0);
  b.fetch.mockResolvedValue(response(state({ status: "failed", error: "Repository unavailable" })));
  await b.listeners.get("retry")?.();
  expect(b.error.textContent).toBe("Repository unavailable");
  expect(b.timers.size).toBe(0);
  expect(b.fetch.mock.calls.every((call) => call[0] === "/scans/opaque/status")).toBe(true);
  b.fetch.mockResolvedValue({ ok: false, status: 404 });
  await b.listeners.get("retry")?.();
  expect(b.location.reload).toHaveBeenCalledTimes(1);
});
it("home/report pages never poll and copying uses exact displayed text", async () => {
  const b = browser(false);
  b.run();
  expect(b.fetch).not.toHaveBeenCalled();
  await b.listeners.get("copy")?.();
  expect(b.clipboard.writeText).toHaveBeenCalledWith(
    "  Exact <evidence> & remediation\nVerify it.\n",
  );
  expect(b.copyStatus.textContent).toContain("Copied");
  expect(b.timers.size).toBe(0);
});
it("clipboard rejection selects the exact prompt and never claims success", async () => {
  const b = browser(false);
  b.clipboard.writeText.mockRejectedValue(new Error("denied"));
  b.run();
  await b.listeners.get("copy")?.();
  expect(b.selected()).toBe("  Exact <evidence> & remediation\nVerify it.\n");
  expect(b.copyStatus.textContent).toContain("Select");
  expect(b.copyStatus.textContent).not.toContain("Copied");
});

it("reconnects the shipped script to the same HTTP job and reaches its report without another submission", async () => {
  const app = createBrowserFixture();
  await new Promise<void>((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  const received: { method: string | undefined; path: string | undefined }[] = [];
  app.server.prependListener("request", (request) =>
    received.push({ method: request.method, path: request.url }),
  );
  try {
    const accepted = await fetch(`${base}/scans`, {
      method: "POST",
      headers: { origin: base, "content-type": "application/x-www-form-urlencoded" },
      body: "repository=https://github.com/owner/repo",
      redirect: "manual",
    });
    expect(accepted.status).toBe(303);
    const path = accepted.headers.get("location") as string;
    const b = browser();
    b.location.pathname = path;
    let offline = true;
    b.fetch.mockImplementation(async (url, options) => {
      if (offline) throw new Error("Connection lost");
      return fetch(`${base}${url}`, options as RequestInit);
    });
    b.run();
    await settle();
    expect(b.retry.hidden).toBe(false);
    expect(b.error.textContent).toContain("lost the connection");
    offline = false;
    await b.listeners.get("retry")?.();
    expect(b.status.textContent).toMatch(/^\d+ of 9 steps done$/);
    expect(b.error.textContent).toBe("");
    app.sandbox.releaseAll();
    await expect.poll(() => app.jobs.get(path.split("/")[2] ?? "")?.status).toBe("completed");
    await [...b.timers.values()][0]?.callback();
    expect(b.location.assign).toHaveBeenCalledWith(`${path}/report`);
    expect(received).toEqual([
      { method: "POST", path: "/scans" },
      { method: "GET", path: `${path}/status` },
      { method: "GET", path: `${path}/status` },
    ]);
    expect(app.sandbox.created).toHaveLength(1);
  } finally {
    await app.shutdown();
    expect(app.sandbox.sessions.size).toBe(0);
    expect(app.clock.pending()).toBe(0);
  }
});

// A queued page that stops polling never notices its own turn arriving.
it("keeps polling and says what is happening while a scan is queued", async () => {
  const b = browser();
  b.fetch.mockResolvedValue(response(state({ status: "waiting", stages: [] })));
  b.run();
  await settle();
  expect(b.status.textContent).toContain("starts on its own");
  expect([...b.timers.values()].map((timer) => timer.ms)).toEqual([2000]);
  expect(b.location.assign).not.toHaveBeenCalled();
});
