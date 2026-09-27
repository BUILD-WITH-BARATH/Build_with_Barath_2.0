package cyberaccess

import (
	"errors"
	"fmt"
)

// ErrInvalidAPIKey is returned when the CyberAccess API rejects the configured
// API key (HTTP 401). Unlike a network failure, this never falls back to
// fail-open/fail-closed behavior - a bad key is a caller misconfiguration,
// not a transient outage.
var ErrInvalidAPIKey = errors.New("cyberaccess: invalid API key")

// BlockedError is returned by AuthorizeOrError when the behavioral risk
// engine's decision is "block" - the request should be rejected even if the
// caller's own authorization check said yes. Use errors.As to recover the
// underlying AuthorizeResult (score, category, signals) for logging.
type BlockedError struct {
	Result AuthorizeResult
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("cyberaccess: blocked (score=%v category=%s signals=%v)", e.Result.Score, e.Result.Category, e.Result.Signals)
}
