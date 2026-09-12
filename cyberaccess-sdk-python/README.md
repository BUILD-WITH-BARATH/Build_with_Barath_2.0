# cyberaccess-sdk

Drop-in BOLA/IDOR behavioral defense for Python APIs. A thin client for CyberAccess's
`/v1/authorize` product API — call it on every request instead of hosting your whole
API through us.

## Install

```bash
pip install cyberaccess-sdk
# or, with the FastAPI helper:
pip install "cyberaccess-sdk[fastapi]"
```

## How it works

Your app already knows how to check ownership (`record.owner_id == user.id`, or whatever
your model is) — that logic stays entirely yours, we never see your data. On every
request, you report your own `authorized` decision to us; we run our behavioral risk
engine on top of it and hand back a final decision. Your `authorized=True` can still come
back as `"block"` if the subject's overall request pattern looks like an attack — that's
the part your own ownership check structurally can't see.

```python
from cyberaccess_sdk import CyberAccessClient

client = CyberAccessClient(api_key="sk_...", base_url="https://your-backend.example.com")

result = client.authorize(subject="user_123", resource_id="invoice_456", authorized=True)
if result.blocked:
    ...  # reject even though your own check said yes
elif not result.allowed:
    ...  # your own check said no; we agree
else:
    ...  # proceed
```

## FastAPI

```python
from fastapi import Depends
from cyberaccess_sdk import CyberAccessClient
from cyberaccess_sdk.fastapi import enforce

guard = CyberAccessClient(api_key="sk_...", base_url="https://your-backend.example.com")

@app.get("/records/{record_id}")
def get_record(record_id: str, user=Depends(get_current_user)):
    is_owner = record_id in user.owned_record_ids  # your own logic
    enforce(guard, subject=user.id, resource_id=record_id, authorized=is_owner)
    return fetch_record(record_id)
```

`enforce()` raises `HTTPException(403)` on a `"deny"` or `"block"` decision; otherwise
returns the `AuthorizeResult` (inspect `.score` / `.signals` if you want to log
high-but-not-blocking risk).

## Flask / Django / plain scripts

```python
from cyberaccess_sdk import CyberAccessClient, CyberAccessBlocked

client = CyberAccessClient(api_key="sk_...", base_url="https://your-backend.example.com")

try:
    result = client.authorize_or_raise(subject=user_id, resource_id=record_id, authorized=is_owner)
except CyberAccessBlocked as exc:
    abort(403, str(exc))
if not result.allowed:
    abort(403)
```

## Fail-open vs fail-closed

If the CyberAccess API is unreachable or times out, the client defaults to **fail-open**:
it falls back to honoring your own `authorized` flag rather than raising, so a network
blip on our side never takes your API down. Pass `fail_open=False` if you'd rather treat
"can't reach the risk engine" as a reason to deny instead.

```python
client = CyberAccessClient(api_key="sk_...", base_url="...", fail_open=False, timeout=5.0)
```

The fallback result's `decision` is always `"allow"` or `"deny"` — never `"block"`,
since a block reflects a genuine behavioral-risk finding, not a network failure.

## Development

```bash
pip install -e ".[fastapi,dev]"
pytest -q
```

All tests run against a mocked HTTP layer (`respx`) — no live backend needed.
