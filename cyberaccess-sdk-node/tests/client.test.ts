import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CyberAccessClient } from "../src/client.js";
import { CyberAccessAuthError, CyberAccessBlocked } from "../src/errors.js";

const BASE_URL = "https://backend.example.com";

function mockFetchOnce(status: number, body: unknown): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }))
  );
}

describe("CyberAccessClient.authorize", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns the parsed decision on success", async () => {
    mockFetchOnce(200, { decision: "allow", score: 5, category: "Normal", signals: [], explanations: [] });
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL });

    const result = await client.authorize("user_1", "record_1", true);

    expect(result.decision).toBe("allow");
    expect(result.score).toBe(5);
    expect(fetch).toHaveBeenCalledWith(
      `${BASE_URL}/v1/authorize`,
      expect.objectContaining({ method: "POST" })
    );
  });

  it("overrides authorized=true with block when the risk engine flags it", async () => {
    mockFetchOnce(200, {
      decision: "block",
      score: 97,
      category: "Attack",
      signals: ["sequential_id_enumeration"],
      explanations: ["Sequential ID enumeration detected"],
    });
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL });

    const result = await client.authorize("attacker_1", "record_5", true);

    expect(result.decision).toBe("block");
    expect(result.signals).toContain("sequential_id_enumeration");
  });

  it("throws CyberAccessAuthError on 401 and does not fall back", async () => {
    mockFetchOnce(401, { detail: "bad key" });
    const client = new CyberAccessClient({ apiKey: "sk_bad", baseUrl: BASE_URL });

    await expect(client.authorize("user_1", "record_1", true)).rejects.toBeInstanceOf(CyberAccessAuthError);
  });

  it("fails open (honors caller's authorized flag) when the API is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      })
    );
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL, failOpen: true });

    const allowed = await client.authorize("user_1", "record_1", true);
    const denied = await client.authorize("user_1", "record_2", false);

    expect(allowed.decision).toBe("allow");
    expect(denied.decision).toBe("deny");
    expect(allowed.explanations[0]).toMatch(/failed open/i);
  });

  it("fails closed (always deny) when configured and the API is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      })
    );
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL, failOpen: false });

    const result = await client.authorize("user_1", "record_1", true);

    expect(result.decision).toBe("deny");
    expect(result.explanations[0]).toMatch(/failed closed/i);
  });

  it("never returns block from a network-failure fallback", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      })
    );
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL, failOpen: false });

    const result = await client.authorize("user_1", "record_1", true);

    expect(result.decision).not.toBe("block");
  });
});

describe("CyberAccessClient.authorizeOrThrow", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("throws CyberAccessBlocked on a block decision", async () => {
    mockFetchOnce(200, { decision: "block", score: 100, category: "Attack", signals: ["canary"], explanations: [] });
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL });

    await expect(client.authorizeOrThrow("attacker_1", "canary_admin_vault", true)).rejects.toBeInstanceOf(
      CyberAccessBlocked
    );
  });

  it("returns the result without throwing on allow/deny", async () => {
    mockFetchOnce(200, { decision: "deny", score: 10, category: "Normal", signals: [], explanations: [] });
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL });

    const result = await client.authorizeOrThrow("user_1", "record_1", false);
    expect(result.decision).toBe("deny");
  });
});

describe("CyberAccessClient.authorizeBatch", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns the batch response on success", async () => {
    mockFetchOnce(200, {
      total: 2,
      blocked_mid_batch: false,
      results: [
        { resource_id: "1", decision: "allow", score: 0, signals: [] },
        { resource_id: "2", decision: "deny", score: 20, signals: [] },
      ],
    });
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL });

    const result = await client.authorizeBatch("user_1", [
      { resource_id: "1", authorized: true },
      { resource_id: "2", authorized: false },
    ]);

    expect(result.total).toBe(2);
    expect(result.results[1].decision).toBe("deny");
  });

  it("falls back per-item when the API is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      })
    );
    const client = new CyberAccessClient({ apiKey: "sk_test", baseUrl: BASE_URL, failOpen: true });

    const result = await client.authorizeBatch("user_1", [
      { resource_id: "1", authorized: true },
      { resource_id: "2", authorized: false },
    ]);

    expect(result.results[0].decision).toBe("allow");
    expect(result.results[1].decision).toBe("deny");
  });
});
