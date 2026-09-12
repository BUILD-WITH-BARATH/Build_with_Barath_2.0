from __future__ import annotations


class CyberAccessError(Exception):
    """Base class for all SDK-raised errors."""


class CyberAccessBlocked(CyberAccessError):
    """Raised by the enforcing helpers (e.g. fastapi.enforce) when the risk
    engine's decision is "block" - the request should be rejected even if the
    caller's own authorization check said yes."""

    def __init__(self, reason: str = "Blocked: suspicious access pattern detected"):
        self.reason = reason
        super().__init__(reason)
