import type { Request, Response, NextFunction } from "express";
import { CyberAccessClient, type AuthorizeResult } from "./client.js";

/**
 * Express middleware factory. Call this at the top of a route (after you've
 * already computed your own `authorized` flag via `resolveAuthorized`)
 * instead of calling `client.authorize()` directly.
 *
 * Responds with 403 if the final decision is "deny" or "block" - your own
 * `authorized: true` can still be overridden to "block" by the behavioral
 * risk engine. Calls `next()` on "allow", attaching the result to
 * `req.cyberaccess` so downstream handlers can inspect `.score` / `.signals`.
 *
 * Example:
 *   const guard = new CyberAccessClient({ apiKey: "sk_...", baseUrl: "https://your-backend.example.com" });
 *
 *   app.get("/records/:id", enforce(guard, (req) => ({
 *     subject: req.user.id,
 *     resourceId: req.params.id,
 *     authorized: req.user.ownedRecordIds.includes(req.params.id),
 *   })), (req, res) => {
 *     res.json(fetchRecord(req.params.id));
 *   });
 */
export function enforce(
  client: CyberAccessClient,
  resolveAuthorized: (req: Request) => { subject: string; resourceId: string | number; authorized: boolean }
) {
  return async function cyberAccessEnforce(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { subject, resourceId, authorized } = resolveAuthorized(req);
    let result: AuthorizeResult;
    try {
      result = await client.authorize(subject, resourceId, authorized);
    } catch (err) {
      next(err);
      return;
    }

    if (result.decision === "block") {
      res.status(403).json({
        outcome: "blocked",
        reason: "Behavioral risk engine detected a suspicious access pattern",
        score: result.score,
        category: result.category,
        signals: result.signals,
      });
      return;
    }
    if (result.decision === "deny") {
      res.status(403).json({ outcome: "denied", score: result.score, category: result.category });
      return;
    }

    (req as Request & { cyberaccess?: AuthorizeResult }).cyberaccess = result;
    next();
  };
}
