import type { Request, Response } from "express";

const allowedHosts = new Set(["api.example.test"]);

export async function proxy(request: Request, response: Response) {
  const target = new URL(String(request.query.url));
  if (!allowedHosts.has(target.hostname)) {
    return response.status(400).send("blocked");
  }
  response.send(await fetch(target).then((result) => result.text()));
}
