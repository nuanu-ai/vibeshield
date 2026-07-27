import type { Request, Response } from "express";

export async function imageProxy(request: Request, response: Response) {
  response.send(await fetch(String(request.query.imageUrl)).then((result) => result.arrayBuffer()));
}

export async function webhookProbe(request: Request, response: Response) {
  response.send(await fetch(String(request.query.webhookUrl)).then((result) => result.text()));
}
