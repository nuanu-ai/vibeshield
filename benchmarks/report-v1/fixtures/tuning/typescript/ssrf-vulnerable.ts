import type { Request, Response } from "express";

export async function proxy(request: Request, response: Response) {
  const target = String(request.query.url);
  response.send(await fetch(target).then((result) => result.text()));
}
