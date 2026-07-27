import type { Request, Response } from "express";

export function echo(request: Request, response: Response) {
  response.json({ value: String(request.query.value) });
}
