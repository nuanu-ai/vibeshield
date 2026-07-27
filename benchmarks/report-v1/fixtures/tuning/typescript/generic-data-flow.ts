import type { Request, Response } from "express";

export function rememberDisplayName(request: Request, response: Response) {
  const displayName = String(request.query.displayName);
  response.locals.auditLabel = displayName;
  response.sendStatus(204);
}
