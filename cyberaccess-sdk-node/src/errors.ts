/** Base class for all SDK-raised errors. */
export class CyberAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CyberAccessError";
  }
}

/**
 * Raised by the enforcing helpers (e.g. `enforce()` in `cyberaccess-sdk/express`)
 * when the risk engine's decision is "block" - the request should be rejected
 * even if the caller's own authorization check said yes.
 */
export class CyberAccessBlocked extends CyberAccessError {
  constructor(message = "Blocked: suspicious access pattern detected") {
    super(message);
    this.name = "CyberAccessBlocked";
  }
}

/** Raised when the configured API key is rejected by the CyberAccess API. */
export class CyberAccessAuthError extends CyberAccessError {
  constructor(message = "Invalid CyberAccess API key") {
    super(message);
    this.name = "CyberAccessAuthError";
  }
}
