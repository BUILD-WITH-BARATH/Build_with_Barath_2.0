"""FastAPI-specific convenience layer. Requires the `fastapi` extra:
    pip install cyberaccess-sdk[fastapi]
"""
from __future__ import annotations

from fastapi import HTTPException

from .client import AuthorizeResult, CyberAccessClient, AsyncCyberAccessClient


def enforce(client: CyberAccessClient, subject: str, resource_id: str, authorized: bool) -> AuthorizeResult:
    """Call this at the top of a route (after you've already computed your own
    `authorized` flag) instead of calling `client.authorize()` directly.
    Raises HTTPException(403) if the final decision is "deny" or "block" -
    your own `authorized=True` can still be overridden to "block" by the
    behavioral risk engine. Returns the AuthorizeResult on "allow" so you can
    inspect score/signals if you want (e.g. to log high-but-not-blocking risk).

    Example:
        guard = CyberAccessClient(api_key="sk_...", base_url="https://your-backend.example.com")

        @app.get("/records/{record_id}")
        def get_record(record_id: str, user=Depends(get_current_user)):
            is_owner = record_id in user.owned_record_ids
            enforce(guard, subject=user.id, resource_id=record_id, authorized=is_owner)
            return fetch_record(record_id)
    """
    result = client.authorize(subject, resource_id, authorized)
    if result.decision == "block":
        raise HTTPException(403, detail={
            "outcome": "blocked",
            "reason": "Behavioral risk engine detected a suspicious access pattern",
            "score": result.score,
            "category": result.category,
            "signals": result.signals,
        })
    if result.decision == "deny":
        raise HTTPException(403, detail={"outcome": "denied", "score": result.score, "category": result.category})
    return result


async def async_enforce(client: AsyncCyberAccessClient, subject: str, resource_id: str, authorized: bool) -> AuthorizeResult:
    """Asynchronous equivalent of `enforce()`, designed for async FastAPI route handlers."""
    result = await client.authorize(subject, resource_id, authorized)
    if result.decision == "block":
        raise HTTPException(403, detail={
            "outcome": "blocked",
            "reason": "Behavioral risk engine detected a suspicious access pattern",
            "score": result.score,
            "category": result.category,
            "signals": result.signals,
        })
    if result.decision == "deny":
        raise HTTPException(403, detail={"outcome": "denied", "score": result.score, "category": result.category})
    return result
