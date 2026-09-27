package cyberaccess_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	cyberaccess "github.com/BUILD-WITH-BARATH/cyberaccess-sdk-go"
)

func TestEnforce_BlocksOnBlockDecision(t *testing.T) {
	upstream := newTestServer(t, http.StatusOK, map[string]any{
		"decision": "block", "score": 100, "category": "Attack", "signals": []string{"canary"}, "explanations": []string{},
	})
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL(upstream.URL))

	nextCalled := false
	handler := cyberaccess.Enforce(client, func(r *http.Request) (string, string, bool) {
		return "attacker_1", "canary_admin_vault", true
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/records/canary_admin_vault", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
	if nextCalled {
		t.Error("next handler should not run on a block decision")
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["outcome"] != "blocked" {
		t.Errorf("expected outcome=blocked, got %v", body["outcome"])
	}
}

func TestEnforce_CallsNextOnAllow(t *testing.T) {
	upstream := newTestServer(t, http.StatusOK, map[string]any{
		"decision": "allow", "score": 0, "category": "Normal", "signals": []string{}, "explanations": []string{},
	})
	client := cyberaccess.NewClient("sk_test", cyberaccess.WithBaseURL(upstream.URL))

	var gotResult cyberaccess.AuthorizeResult
	var gotOK bool
	handler := cyberaccess.Enforce(client, func(r *http.Request) (string, string, bool) {
		return "user_1", "record_1", true
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotResult, gotOK = cyberaccess.ResultFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/records/1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !gotOK {
		t.Error("expected AuthorizeResult to be attached to the request context")
	}
	if gotResult.Decision != cyberaccess.DecisionAllow {
		t.Errorf("expected allow, got %s", gotResult.Decision)
	}
}
