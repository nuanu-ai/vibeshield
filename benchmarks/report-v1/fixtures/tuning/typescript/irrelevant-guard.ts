import type { Request, Response } from "express";

export async function proxy(request: Request, response: Response) {
  const target = String(request.query.url);
  if (!request.user?.canReadInvoices) {
    return response.status(403).send("forbidden");
  }
  response.send(await fetch(target).then((result) => result.text()));
}
