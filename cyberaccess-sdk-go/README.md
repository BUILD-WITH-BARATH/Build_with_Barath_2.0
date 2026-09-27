# cyberaccess-sdk-go

Drop-in BOLA/IDOR behavioral defense for Go APIs. A thin client for CyberAccess's
`/v1/authorize` product API — call it on every request instead of hosting your whole
API through us.

## Install

```bash
go get github.com/BUILD-WITH-BARATH/cyberaccess-sdk-go
```

## How it works

Your app already knows how to check ownership (`record.OwnerID == user.ID`, or whatever
your model is) — that logic stays entirely yours, we never see your data. On every
request, you report your own `authorized` decision to us; we run our behavioral risk
engine on top of it and hand back a final decision. Your `authorized=true` can still
come back as `"block"` if the subject's overall request pattern looks like an attack —
that's the part your own ownership check structurally can't see.

```go
client := cyberaccess.NewClient("sk_...", cyberaccess.WithBaseURL("https://your-backend.example.com"))

result, err := client.Authorize(ctx, "user_123", "invoice_456", true /* authorized */)
if err != nil {
    // ErrInvalidAPIKey, or a transport error if you constructed the client
    // with WithFailClosed() disabled fallback handling for some other reason
}
switch {
case result.Blocked():
    // reject even though your own check said yes
case result.Decision == cyberaccess.DecisionDeny:
    // your own check said no; we agree
default:
    // proceed
}
```

## net/http (works with any router built on it: chi, gorilla/mux, stdlib ServeMux)

```go
guard := cyberaccess.NewClient("sk_...", cyberaccess.WithBaseURL("https://your-backend.example.com"))

http.Handle("/records/", cyberaccess.Enforce(guard, func(r *http.Request) (subject, resourceID string, authorized bool) {
    id := path.Base(r.URL.Path)
    user := userFromRequest(r)
    return user.ID, id, user.OwnsRecord(id) // your own logic
}, recordsHandler))
```

`Enforce` responds `403` on a `"deny"` or `"block"` decision; otherwise it calls the
wrapped handler with the `AuthorizeResult` available via
`cyberaccess.ResultFromContext(r.Context())` (inspect `.Score` / `.Signals` if you want
to log high-but-not-blocking risk).

## Plain Go / other frameworks

```go
result, err := client.AuthorizeOrError(ctx, userID, recordID, isOwner)
var blocked *cyberaccess.BlockedError
if errors.As(err, &blocked) {
    // reject - behavioral risk engine flagged this
}
if result.Decision == cyberaccess.DecisionDeny {
    // reject
}
```

## Fail-open vs fail-closed

If the CyberAccess API is unreachable or times out, the client defaults to **fail-open**:
it falls back to honoring your own `authorized` flag rather than returning an error, so a
network blip on our side never takes your API down. Pass `cyberaccess.WithFailClosed()`
if you'd rather treat "can't reach the risk engine" as a reason to deny instead.

```go
client := cyberaccess.NewClient(
    "sk_...",
    cyberaccess.WithBaseURL("..."),
    cyberaccess.WithFailClosed(),
    cyberaccess.WithTimeout(5*time.Second),
)
```

The fallback result's `Decision` is always `DecisionAllow` or `DecisionDeny` — never
`DecisionBlock`, since a block reflects a genuine behavioral-risk finding, not a network
failure.

## Development

```bash
go build ./...
go vet ./...
go test ./... -v
```

All tests run against `net/http/httptest` - no live backend needed.
