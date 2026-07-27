import { execFile } from "node:child_process";
import type { Request, Response } from "express";

export function convert(request: Request, response: Response) {
  execFile("convert", [String(request.query.input)], (error, stdout) => {
    response.status(error === null ? 200 : 500).send(stdout);
  });
}
