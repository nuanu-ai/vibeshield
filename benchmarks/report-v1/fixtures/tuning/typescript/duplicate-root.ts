import type { Request, Response } from "express";

async function fetchUrl(target: string) {
  return fetch(target).then((result) => result.text());
}

export async function proxyGet(request: Request, response: Response) {
  response.send(await fetchUrl(String(request.query.url)));
}

export async function proxyPost(request: Request, response: Response) {
  response.send(await fetchUrl(String(request.body.url)));
}
