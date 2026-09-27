package cyberaccess_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cyberaccess "github.com/BUILD-WITH-BARATH/cyberaccess-sdk-go"
)

func newTestServer(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestAuthorize_Success(t *testing.T) {
	server := newTestServer(t, http.StatusOK, map[string]any{
		"decision": "allow", "score": 5, "category": "Normal", "signals": []string{}, "explanations": []string{},
	})
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL(server.URL))

	result, err := client.Authorize(context.Background(), "user_1", "record_1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != cyberaccess.DecisionAllow {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

func TestAuthorize_OverridesTrueWithBlock(t *testing.T) {
	server := newTestServer(t, http.StatusOK, map[string]any{
		"decision": "block", "score": 97, "category": "Attack",
		"signals": []string{"sequential_id_enumeration"}, "explanations": []string{"..."},
	})
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL(server.URL))

	result, err := client.Authorize(context.Background(), "attacker_1", "record_5", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Blocked() {
		t.Errorf("expected blocked=true, got decision=%s", result.Decision)
	}
}

func TestAuthorize_InvalidAPIKeyDoesNotFallBack(t *testing.T) {
	server := newTestServer(t, http.StatusUnauthorized, map[string]any{"detail": "bad key"})
	client := cyberaccess.NewClient("sk_bad", cyberaccess.WithBaseURL(server.URL))

	_, err := client.Authorize(context.Background(), "user_1", "record_1", true)
	if !errors.Is(err, cyberaccess.ErrInvalidAPIKey) {
		t.Fatalf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestAuthorize_FailsOpenOnUnreachableAPI(t *testing.T) {
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL("http://127.0.0.1:1"), cyberaccess.WithTimeout(200*time.Millisecond))

	allowed, err := client.Authorize(context.Background(), "user_1", "record_1", true)
	if err != nil {
		t.Fatalf("fail-open should not return an error, got %v", err)
	}
	if allowed.Decision != cyberaccess.DecisionAllow {
		t.Errorf("expected allow (honoring authorized=true), got %s", allowed.Decision)
	}

	denied, err := client.Authorize(context.Background(), "user_1", "record_2", false)
	if err != nil {
		t.Fatalf("fail-open should not return an error, got %v", err)
	}
	if denied.Decision != cyberaccess.DecisionDeny {
		t.Errorf("expected deny (honoring authorized=false), got %s", denied.Decision)
	}
}

func TestAuthorize_FailsClosedWhenConfigured(t *testing.T) {
	client := cyberaccess.NewClient(
		"sk_test",
		cyberaccess.WithBaseURL("http://127.0.0.1:1"),
		cyberaccess.WithTimeout(200*time.Millisecond),
		cyberaccess.WithFailClosed(),
	)

	result, err := client.Authorize(context.Background(), "user_1", "record_1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != cyberaccess.DecisionDeny {
		t.Errorf("expected deny under fail-closed, got %s", result.Decision)
	}
}

func TestAuthorize_FallbackNeverReturnsBlock(t *testing.T) {
	client := cyberaccess.NewClient(
		"sk_test",
		cyberaccess.WithBaseURL("http://127.0.0.1:1"),
		cyberaccess.WithTimeout(200*time.Millisecond),
		cyberaccess.WithFailClosed(),
	)

	result, _ := client.Authorize(context.Background(), "user_1", "record_1", true)
	if result.Blocked() {
		t.Errorf("a network-failure fallback must never report Blocked()==true")
	}
}

func TestAuthorizeOrError_ReturnsBlockedErrorOnBlock(t *testing.T) {
	server := newTestServer(t, http.StatusOK, map[string]any{
		"decision": "block", "score": 100, "category": "Attack", "signals": []string{"canary"}, "explanations": []string{},
	})
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL(server.URL))

	_, err := client.AuthorizeOrError(context.Background(), "attacker_1", "canary_admin_vault", true)
	var blockedErr *cyberaccess.BlockedError
	if !errors.As(err, &blockedErr) {
		t.Fatalf("expected *BlockedError, got %v (%T)", err, err)
	}
}

func TestAuthorizeOrError_NoErrorOnDeny(t *testing.T) {
	server := newTestServer(t, http.StatusOK, map[string]any{
		"decision": "deny", "score": 10, "category": "Normal", "signals": []string{}, "explanations": []string{},
	})
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL(server.URL))

	result, err := client.AuthorizeOrError(context.Background(), "user_1", "record_1", false)
	if err != nil {
		t.Fatalf("expected no error on deny, got %v", err)
	}
	if result.Decision != cyberaccess.DecisionDeny {
		t.Errorf("expected deny, got %s", result.Decision)
	}
}

func TestAuthorizeBatch_Success(t *testing.T) {
	server := newTestServer(t, http.StatusOK, map[string]any{
		"total": 2, "blocked_mid_batch": false,
		"results": []map[string]any{
			{"resource_id": "1", "decision": "allow", "score": 0, "signals": []string{}},
			{"resource_id": "2", "decision": "deny", "score": 20, "signals": []string{}},
		},
	})
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL(server.URL))

	result, err := client.AuthorizeBatch(context.Background(), "user_1", []cyberaccess.BatchItem{
		{ResourceID: "1", Authorized: true},
		{ResourceID: "2", Authorized: false},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Total != 2 || result.Results[1].Decision != cyberaccess.DecisionDeny {
		t.Errorf("unexpected batch result: %+v", result)
	}
}

func TestAuthorizeBatch_FallsBackPerItemWhenUnreachable(t *testing.T) {
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL("http://127.0.0.1:1"), cyberaccess.WithTimeout(200*time.Millisecond))

	result, err := client.AuthorizeBatch(context.Background(), "user_1", []cyberaccess.BatchItem{
		{ResourceID: "1", Authorized: true},
		{ResourceID: "2", Authorized: false},
	})
	if err != nil {
		t.Fatalf("fail-open batch should not return an error, got %v", err)
	}
	if result.Results[0].Decision != cyberaccess.DecisionAllow || result.Results[1].Decision != cyberaccess.DecisionDeny {
		t.Errorf("unexpected fallback batch result: %+v", result.Results)
	}
}
