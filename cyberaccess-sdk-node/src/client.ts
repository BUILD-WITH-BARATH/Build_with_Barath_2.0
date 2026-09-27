import { CyberAccessAuthError, CyberAccessBlocked } from "./errors.js";

export type Decision = "allow" | "deny" | "block";

/** Mirrors the JSON body of POST /v1/authorize. */
export interface AuthorizeResult {
  decision: Decision;
  score: number;
  category: string;
  signals: string[];
  explanations: string[];
}

export interface AuthorizeBatchItem {
  resource_id: string | number;
  authorized: boolean;
  http_verb?: string;
}

export interface AuthorizeBatchResult {
  total: number;
  blocked_mid_batch: boolean;
  results: Array<{
    resource_id: string;
    decision: Decision;
    score: number;
    signals: string[];
  }>;
}

export interface CyberAccessClientOptions {
  apiKey: string;
  baseUrl?: string;
  /** Request timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
  /**
   * If the CyberAccess API is unreachable or times out, fall back to honoring
   * the caller's own `authorized` flag ("allow"/"deny", never "block" - a
   * block reflects a genuine behavioral-risk finding, not a network failure).
   * Pass `false` to fail closed (always "deny") instead. Default true.
   */
  failOpen?: boolean;
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === "AbortError";
}

/**
 * Thin client for the CyberAccess `/v1/authorize` product API.
 *
 * Framework-agnostic - call `.authorize()` directly from any Node.js app, or
 * use `enforce()` from `@cyberaccess/sdk/express` for a drop-in middleware
 * helper that rejects on a "block" decision.
 *
 * Fail-open by default: if the CyberAccess API is unreachable or times out,
 * `.authorize()` returns an "allow"/"deny" result (honoring your own
 * `authorized` flag) rather than throwing, so a network blip on our side
 * never takes your API down. Pass `failOpen: false` if you'd rather treat
 * "can't reach the risk engine" as a reason to deny instead.
 */
export class CyberAccessClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly failOpen: boolean;

  constructor(options: CyberAccessClientOptions) {
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? "https://api.cyberaccess.dev").replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.failOpen = options.failOpen ?? true;
  }

  /**
   * Reports your own authorization decision (`authorized`) for this
   * subject/resource pair and gets back the behavioral-risk-adjusted final
   * decision. `authorized: true` can still come back as "block" if the
   * subject's overall request pattern looks like an attack in progress.
   */
  async authorize(subject: string, resourceId: string | number, authorized: boolean): Promise<AuthorizeResult> {
    return this.postAuthorize({ subject, resource_id: String(resourceId), authorized }, authorized);
  }

  /** Evaluates write/mutation actions (PUT, PATCH, DELETE) with verb-weighted risk penalties. */
  async authorizeMutation(
    subject: string,
    resourceId: string | number,
    authorized: boolean,
    httpVerb: string = "PUT"
  ): Promise<AuthorizeResult> {
    return this.postAuthorize(
      { subject, resource_id: String(resourceId), authorized, http_verb: httpVerb },
      authorized
    );
  }

  /**
   * Framework-agnostic equivalent of `enforce()` from `@cyberaccess/sdk/express` -
   * use this outside Express (plain scripts, other frameworks, workers). Throws
   * `CyberAccessBlocked` on a "block" decision; returns the result (never throws)
   * for "allow" or "deny" - checking `.decision === "deny"` is on you.
   */
  async authorizeOrThrow(subject: string, resourceId: string | number, authorized: boolean): Promise<AuthorizeResult> {
    const result = await this.authorize(subject, resourceId, authorized);
    if (result.decision === "block") {
      throw new CyberAccessBlocked(
        `Blocked: score=${result.score} category=${result.category} signals=${JSON.stringify(result.signals)}`
      );
    }
    return result;
  }

  /** Evaluates an array of resource requests with atomic batch limits and mid-batch blocking. */
  async authorizeBatch(subject: string, items: AuthorizeBatchItem[]): Promise<AuthorizeBatchResult> {
    try {
      const body = await this.postJson("/v1/authorize-batch", { subject, items });
      return body as AuthorizeBatchResult;
    } catch (err) {
      if (err instanceof CyberAccessAuthError) throw err;
      return this.batchFallback(items);
    }
  }

  private batchFallback(items: AuthorizeBatchItem[]): AuthorizeBatchResult {
    return {
      total: items.length,
      blocked_mid_batch: false,
      results: items.map((item) => ({
        resource_id: String(item.resource_id),
        decision: this.failOpen ? (item.authorized ? "allow" : "deny") : "deny",
        score: 0,
        signals: [],
      })),
    };
  }

  private async postAuthorize(payload: Record<string, unknown>, authorized: boolean): Promise<AuthorizeResult> {
    try {
      const body = await this.postJson("/v1/authorize", payload);
      return {
        decision: body.decision,
        score: body.score,
        category: body.category,
        signals: body.signals ?? [],
        explanations: body.explanations ?? [],
      };
    } catch (err) {
      if (err instanceof CyberAccessAuthError) throw err;
      return this.fallback(authorized);
    }
  }

  private fallback(authorized: boolean): AuthorizeResult {
    // "deny" here, never "block" - block is reserved for a genuine
    // behavioral-risk decision from the engine, which this isn't.
    if (this.failOpen) {
      return {
        decision: authorized ? "allow" : "deny",
        score: 0,
        category: "Unknown",
        signals: [],
        explanations: ["CyberAccess API unreachable - failed open"],
      };
    }
    return {
      decision: "deny",
      score: 0,
      category: "Unknown",
      signals: [],
      explanations: ["CyberAccess API unreachable - failed closed"],
    };
  }

  private async postJson(path: string, payload: unknown): Promise<any> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": this.apiKey },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (response.status === 401) {
        throw new CyberAccessAuthError();
      }
      if (!response.ok) {
        throw new Error(`CyberAccess API returned ${response.status}`);
      }
      return await response.json();
    } catch (err) {
      if (err instanceof CyberAccessAuthError) throw err;
      if (isAbortError(err)) throw new Error("CyberAccess API request timed out");
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }
}
