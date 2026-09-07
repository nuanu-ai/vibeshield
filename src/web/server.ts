import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { parseRepositoryUrl } from "../scan/source.js";
import { browserScript, stylesheet } from "./assets.js";
import { BusyError, type JobStore } from "./jobs.js";
import { renderHome, renderProgress, renderReport, renderUnavailable } from "./pages.js";

const bodyLimit = 8 * 1024;
const jobPath =
  /^\/scans\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:\/(status|report))?$/;
const csp =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
class RequestError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function createWebServer(jobs: JobStore): Server {
  const server = createServer(
    { requestTimeout: 15_000, headersTimeout: 10_000, maxHeaderSize: 16 * 1024 },
    (request, response) => {
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("X-Content-Type-Options", "nosniff");
      response.setHeader("Content-Security-Policy", csp);
      void handle(request, response).catch((error) => {
        const status =
          error instanceof RequestError ? error.status : error instanceof BusyError ? 409 : 500;
        const message =
          error instanceof RequestError || error instanceof BusyError
            ? error.message
            : "The scan service is temporarily unavailable.";
        response.setHeader("Connection", "close");
        send(response, status, renderHome(message));
      });
    },
  );
  async function handle(request: IncomingMessage, response: ServerResponse) {
    const origin = requestOrigin(request, server);
    const path = request.url ?? "";
    const match = jobPath.exec(path);
    const known =
      path === "/" ||
      path === "/scans" ||
      path === "/assets/app.js" ||
      path === "/assets/app.css" ||
      match;
    if (!known) return send(response, 404, renderUnavailable());
    const method = path === "/scans" ? "POST" : "GET";
    if (request.method !== method) {
      response.setHeader("Allow", method);
      return send(response, 405, renderHome("This request method is not supported."));
    }
    if (path === "/scans") {
      if (
        request.headers.origin !== origin ||
        (request.headers["sec-fetch-site"] !== undefined &&
          request.headers["sec-fetch-site"] !== "same-origin")
      )
        throw new RequestError(400, "Submit the form from this service's home page.");
      if (
        !/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/i.test(
          request.headers["content-type"] ?? "",
        ) ||
        request.headers["content-encoding"] !== undefined
      )
        throw new RequestError(400, "Submit a GitHub repository using the form.");
      const data = new URLSearchParams(await readBody(request));
      if (data.size !== 1 || data.getAll("repository").length !== 1)
        throw new RequestError(400, "Enter one public GitHub repository URL.");
      let url: string;
      try {
        url = parseRepositoryUrl(data.get("repository") ?? "");
      } catch {
        throw new RequestError(400, "Enter a public GitHub repository URL.");
      }
      const { id } = jobs.start(url);
      return redirect(response, `/scans/${id}`);
    }
    if (path === "/")
      return send(
        response,
        200,
        renderHome(
          jobs.busy()
            ? "Another scan is running or cleanup is pending. Please try again later."
            : undefined,
        ),
      );
    if (path === "/assets/app.js") return send(response, 200, browserScript, "text/javascript");
    if (path === "/assets/app.css") return send(response, 200, stylesheet, "text/css");
    const job = jobs.get(match?.[1] ?? "");
    if (!job) return send(response, 404, renderUnavailable());
    if (match?.[2] === "status") {
      return send(
        response,
        200,
        JSON.stringify({
          status: job.status,
          stages: job.stages.map(({ stage, status, message }) => ({ stage, status, message })),
          ...(job.error ? { error: job.error } : {}),
          reportReady: job.status === "completed" && job.report !== undefined,
        }),
        "application/json",
      );
    }
    if (match?.[2] === "report") {
      if (job.status !== "completed" || !job.report) return redirect(response, `/scans/${job.id}`);
      return send(response, 200, renderReport(job.report));
    }
    return send(response, 200, renderProgress(job));
  }
  return server;
}

/** Trust loopback names or the interface that received this connection.
 * Wildcard binds do not make arbitrary DNS names acceptable. */
function requestOrigin(request: IncomingMessage, server: Server): string {
  const host = request.headers.host;
  const address = server.address();
  const hostCount = request.rawHeaders.filter(
    (_, index) => index % 2 === 0 && request.rawHeaders[index]?.toLowerCase() === "host",
  ).length;
  if (!host || hostCount !== 1 || !address || typeof address === "string")
    throw new RequestError(400, "Invalid service address.");
  // Parse the authority before URL canonicalization: URL alone accepts numeric
  // IPv4 shorthand, credentials and other forms that are not service IP literals.
  const authority = /^(?:\[([a-f\d:.]+)\]|(localhost|[\d.]+))(?::(\d+))?$/i.exec(host);
  const literal = authority?.[1] ?? authority?.[2];
  if (
    !literal ||
    (authority?.[1] !== undefined && isIP(literal) !== 6) ||
    (authority?.[3] ?? "80") !== String(address.port)
  )
    throw new RequestError(400, "Invalid service address.");
  const requested = literal.toLowerCase() === "localhost" ? "localhost" : normalizeIp(literal);
  const hosts = new Set(["127.0.0.1", "localhost", "::1"]);
  const local = normalizeIp(request.socket.localAddress ?? "");
  if (local) hosts.add(local);
  if (!requested || !hosts.has(requested)) throw new RequestError(400, "Invalid service address.");
  // Preserve browser origin identity: a mapped-IPv6 URL and a dotted-IPv4 URL
  // share an address, but must not authorize each other's form submissions.
  return new URL(`http://${host}`).origin;
}
function normalizeIp(value: string): string | undefined {
  if (isIP(value) === 4) return value;
  if (isIP(value) !== 6 || value.includes("%")) return undefined;
  const canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  const mapped = /^::ffff:([a-f\d]{1,4}):([a-f\d]{1,4})$/.exec(canonical);
  if (mapped?.[1] && mapped[2]) {
    const high = Number.parseInt(mapped[1], 16);
    const low = Number.parseInt(mapped[2], 16);
    return [high >>> 8, high & 255, low >>> 8, low & 255].join(".");
  }
  return canonical;
}
function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > bodyLimit) {
        reject(new RequestError(413, "Repository submission is too large (maximum 8 KiB)."));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (size > bodyLimit) return;
      try {
        resolve(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
      } catch {
        reject(new RequestError(400, "Submission must use UTF-8 text."));
      }
    });
    request.on("error", () => reject(new RequestError(400, "Submission could not be read.")));
  });
}
function send(response: ServerResponse, status: number, body: string, type = "text/html") {
  response.writeHead(status, { "Content-Type": `${type}; charset=utf-8` }).end(body);
}
function redirect(response: ServerResponse, location: string) {
  response.writeHead(303, { Location: location }).end();
}
