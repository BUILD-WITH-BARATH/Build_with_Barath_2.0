package cyberaccess

import (
	"context"
	"encoding/json"
	"net/http"
)

type contextKey string

const resultContextKey contextKey = "cyberaccess.result"

// Resolver computes the subject/resourceID/authorized triple for an inbound
// request, using whatever authentication and ownership logic your app
// already has. It stays entirely yours - CyberAccess never sees your data.
type Resolver func(r *http.Request) (subject string, resourceID string, authorized bool)

// ResultFromContext recovers the AuthorizeResult that Enforce attached to the
// request context, for handlers that want to inspect .Score / .Signals for
// an allowed request (e.g. to log high-but-not-blocking risk).
func ResultFromContext(ctx context.Context) (AuthorizeResult, bool) {
	result, ok := ctx.Value(resultContextKey).(AuthorizeResult)
	return result, ok
}

// Enforce wraps an http.Handler with a CyberAccess authorization check. It
// calls resolve to get your own authorization decision, reports it to the
// risk engine via client.Authorize, and:
//   - responds 403 if the final decision is "deny" or "block" (your own
//     authorized=true can still be overridden to "block" by the behavioral
//     risk engine),
//   - otherwise calls next, with the AuthorizeResult available via
//     ResultFromContext(r.Context()).
//
// Example:
//
//	guard := cyberaccess.NewClient("sk_...", cyberaccess.WithBaseURL("https://your-backend.example.com"))
//
//	http.Handle("/records/", cyberaccess.Enforce(guard, func(r *http.Request) (string, string, bool) {
//	    id := path.Base(r.URL.Path)
//	    user := userFromRequest(r)
//	    return user.ID, id, user.OwnsRecord(id) // your own logic
//	}, recordsHandler))
func Enforce(client *Client, resolve Resolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, resourceID, authorized := resolve(r)

		result, err := client.Authorize(r.Context(), subject, resourceID, authorized)
		if err != nil {
			http.Error(w, "cyberaccess: authorization check failed", http.StatusBadGateway)
			return
		}

		if result.Blocked() {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"outcome":  "blocked",
				"reason":   "Behavioral risk engine detected a suspicious access pattern",
				"score":    result.Score,
				"category": result.Category,
				"signals":  result.Signals,
			})
			return
		}
		if result.Decision == DecisionDeny {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"outcome":  "denied",
				"score":    result.Score,
				"category": result.Category,
			})
			return
		}

		ctx := context.WithValue(r.Context(), resultContextKey, result)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
