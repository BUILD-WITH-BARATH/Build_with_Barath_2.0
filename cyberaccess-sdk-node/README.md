# @cyberaccess/sdk

Drop-in BOLA/IDOR behavioral defense for Node.js APIs. A thin client for CyberAccess's
`/v1/authorize` product API — call it on every request instead of hosting your whole
API through us.

## Install

```bash
npm install @cyberaccess/sdk
```

## How it works

Your app already knows how to check ownership (`record.ownerId === user.id`, or whatever
your model is) — that logic stays entirely yours, we never see your data. On every
request, you report your own `authorized` decision to us; we run our behavioral risk
engine on top of it and hand back a final decision. Your `authorized: true` can still
come back as `"block"` if the subject's overall request pattern looks like an attack —
that's the part your own ownership check structurally can't see.

```ts
import { CyberAccessClient } from "@cyberaccess/sdk";

const client = new CyberAccessClient({ apiKey: "sk_...", baseUrl: "https://your-backend.example.com" });

const result = await client.authorize("user_123", "invoice_456", /* authorized */ true);
if (result.decision === "block") {
  // reject even though your own check said yes
} else if (result.decision === "deny") {
  // your own check said no; we agree
} else {
  // proceed
}
```

## Express

```ts
import express from "express";
import { CyberAccessClient } from "@cyberaccess/sdk";
import { enforce } from "@cyberaccess/sdk/express";

const guard = new CyberAccessClient({ apiKey: "sk_...", baseUrl: "https://your-backend.example.com" });

app.get(
  "/records/:id",
  enforce(guard, (req) => ({
    subject: req.user.id,
    resourceId: req.params.id,
    authorized: req.user.ownedRecordIds.includes(req.params.id), // your own logic
  })),
  (req, res) => {
    res.json(fetchRecord(req.params.id));
  }
);
```

`enforce()` responds with `403` on a `"deny"` or `"block"` decision; otherwise calls
`next()` and attaches the result to `req.cyberaccess` (inspect `.score` / `.signals` if
you want to log high-but-not-blocking risk).

## Plain Node.js / other frameworks

```ts
import { CyberAccessClient, CyberAccessBlocked } from "@cyberaccess/sdk";

const client = new CyberAccessClient({ apiKey: "sk_...", baseUrl: "https://your-backend.example.com" });

try {
  const result = await client.authorizeOrThrow(userId, recordId, isOwner);
  if (result.decision === "deny") {
    // reject
  }
} catch (err) {
  if (err instanceof CyberAccessBlocked) {
    // reject - behavioral risk engine flagged this
  }
  throw err;
}
```

## Fail-open vs fail-closed

If the CyberAccess API is unreachable or times out, the client defaults to **fail-open**:
it falls back to honoring your own `authorized` flag rather than throwing, so a network
blip on our side never takes your API down. Pass `failOpen: false` if you'd rather treat
"can't reach the risk engine" as a reason to deny instead.

```ts
const client = new CyberAccessClient({
  apiKey: "sk_...",
  baseUrl: "...",
  failOpen: false,
  timeoutMs: 5000,
});
```

The fallback result's `decision` is always `"allow"` or `"deny"` — never `"block"`,
since a block reflects a genuine behavioral-risk finding, not a network failure.

## Development

```bash
npm install
npm run build
npm test
```

All tests run against a mocked `fetch` — no live backend needed.
