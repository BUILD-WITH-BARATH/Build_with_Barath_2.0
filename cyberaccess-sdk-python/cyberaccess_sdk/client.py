from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from .exceptions import CyberAccessBlocked


@dataclass
class AuthorizeResult:
    """Mirrors the JSON body of POST /v1/authorize."""

    decision: str  # "allow" | "deny" | "block"
    score: int
    category: str
    signals: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


class CyberAccessClient:
    """Thin client for the CyberAccess /v1/authorize product API.

    Framework-agnostic - call `.authorize()` directly from any Python app,
    or use the FastAPI-specific helpers in `cyberaccess_sdk.fastapi` for a
    drop-in dependency that raises on a block decision.

    Fail-open by default: if the CyberAccess API is unreachable or times out,
    `.authorize()` returns an "allow" result rather than raising, so a network
    blip on our side never takes your API down. Pass `fail_open=False` if you'd
    rather treat "can't reach the risk engine" as a reason to deny instead.
    """

    def __init__(self, api_key: str, base_url: str = "https://api.cyberaccess.dev",
                 timeout: float = 5.0, fail_open: bool = True):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.fail_open = fail_open
        self._client = httpx.Client(timeout=timeout)

    def authorize(self, subject: str, resource_id: str, authorized: bool) -> AuthorizeResult:
        """Reports your own authorization decision (`authorized`) for this
        subject/resource pair and gets back the behavioral-risk-adjusted
        final decision. `authorized=True` can still come back as "block" if
        the subject's request pattern looks like an attack in progress."""
        try:
            response = self._client.post(
                f"{self.base_url}/v1/authorize",
                json={"subject": subject, "resource_id": str(resource_id), "authorized": authorized},
                headers={"X-API-Key": self.api_key},
            )
            response.raise_for_status()
            body = response.json()
            return AuthorizeResult(
                decision=body["decision"], score=body["score"], category=body["category"],
                signals=body.get("signals", []), explanations=body.get("explanations", []),
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                raise ValueError("Invalid CyberAccess API key") from exc
            return self._fallback(authorized)
        except httpx.RequestError:
            return self._fallback(authorized)

    def _fallback(self, authorized: bool) -> AuthorizeResult:
        # Note: "deny" here, never "block" - block is reserved for a genuine
        # behavioral-risk decision from the engine, which this isn't.
        if self.fail_open:
            return AuthorizeResult(decision="allow" if authorized else "deny", score=0, category="Unknown",
                                    explanations=["CyberAccess API unreachable - failed open"])
        return AuthorizeResult(decision="deny", score=0, category="Unknown",
                                explanations=["CyberAccess API unreachable - failed closed"])

    def authorize_or_raise(self, subject: str, resource_id: str, authorized: bool) -> AuthorizeResult:
        """Framework-agnostic equivalent of cyberaccess_sdk.fastapi.enforce() -
        use this in Flask, Django, or plain scripts. Raises CyberAccessBlocked
        on a "block" decision; returns the result (never raises) for "allow"
        or "deny" - checking `.allowed` is on you for the "deny" case, since
        plain Python has no universal "reject this request" mechanism to
        raise into the way a web framework's HTTPException does."""
        result = self.authorize(subject, resource_id, authorized)
        if result.decision == "block":
            raise CyberAccessBlocked(
                f"Blocked: score={result.score} category={result.category} signals={result.signals}"
            )
        return result

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "CyberAccessClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
