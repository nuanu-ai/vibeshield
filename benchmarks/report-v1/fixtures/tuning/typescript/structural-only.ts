import type { Request, Response } from "express";

export function describeProxy(request: Request, response: Response) {
  const requestedLabel = String(request.query.label);
  response.json({ requestedLabel, implementation: fetch.name });
}
