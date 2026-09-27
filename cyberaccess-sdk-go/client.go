// Package cyberaccess is a thin client for CyberAccess's /v1/authorize product
// API - drop-in BOLA/IDOR behavioral defense for Go APIs. Call it on every
// request instead of hosting your whole API through us.
package cyberaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Decision is the final authorization outcome returned by the risk engine.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionBlock Decision = "block"
)

// AuthorizeResult mirrors the JSON body of POST /v1/authorize.
type AuthorizeResult struct {
	Decision     Decision `json:"decision"`
	Score        float64  `json:"score"`
	Category     string   `json:"category"`
	Signals      []string `json:"signals"`
	Explanations []string `json:"explanations"`
}

// Blocked reports whether the risk engine's decision was "block".
func (r AuthorizeResult) Blocked() bool { return r.Decision == DecisionBlock }

// Allowed reports whether the risk engine's decision was "allow".
func (r AuthorizeResult) Allowed() bool { return r.Decision == DecisionAllow }

// BatchItem is one entry in an AuthorizeBatch request.
type BatchItem struct {
	ResourceID string `json:"resource_id"`
	Authorized bool   `json:"authorized"`
	HTTPVerb   string `json:"http_verb,omitempty"`
}

// BatchResultItem is one entry in an AuthorizeBatch response.
type BatchResultItem struct {
	ResourceID string   `json:"resource_id"`
	Decision   Decision `json:"decision"`
	Score      float64  `json:"score"`
	Signals    []string `json:"signals"`
}

// BatchResult mirrors the JSON body of POST /v1/authorize-batch.
type BatchResult struct {
	Total           int               `json:"total"`
	BlockedMidBatch bool              `json:"blocked_mid_batch"`
	Results         []BatchResultItem `json:"results"`
}

// Client is a thin client for the CyberAccess /v1/authorize product API.
//
// Fail-open by default: if the CyberAccess API is unreachable or times out,
// Authorize returns an "allow"/"deny" result (honoring the caller's own
// `authorized` flag) rather than an error, so a network blip on our side
// never takes your API down. Pass WithFailClosed() if you'd rather treat
// "can't reach the risk engine" as a reason to deny instead.
type Client struct {
	apiKey     string
	baseURL    string
	failOpen   bool
	httpClient *http.Client
}

// Option configures a Client constructed by NewClient.
type Option func(*Client)

// WithBaseURL overrides the default API base URL (https://api.cyberaccess.dev).
func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(url, "/") }
}

// WithTimeout overrides the default 5-second per-request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// WithFailClosed makes Authorize/AuthorizeMutation/AuthorizeBatch return a
// "deny" (never "block" - see the package doc) when the API is unreachable,
// instead of the default fail-open behavior.
func WithFailClosed() Option {
	return func(c *Client) { c.failOpen = false }
}

// WithHTTPClient lets the caller supply their own *http.Client (custom
// transport, proxying, instrumentation, etc). Its Timeout is left as-is
// unless WithTimeout is also passed after this option.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// NewClient constructs a Client for the given API key.
func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:     apiKey,
		baseURL:    "https://api.cyberaccess.dev",
		failOpen:   true,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Authorize reports your own authorization decision (authorized) for this
// subject/resource pair and gets back the behavioral-risk-adjusted final
// decision. authorized=true can still come back as "block" if the subject's
// overall request pattern looks like an attack in progress.
func (c *Client) Authorize(ctx context.Context, subject, resourceID string, authorized bool) (AuthorizeResult, error) {
	payload := map[string]any{"subject": subject, "resource_id": resourceID, "authorized": authorized}
	return c.postAuthorize(ctx, payload, authorized)
}

// AuthorizeMutation evaluates write/mutation actions (PUT, PATCH, DELETE)
// with verb-weighted risk penalties. httpVerb defaults to "PUT" if empty.
func (c *Client) AuthorizeMutation(ctx context.Context, subject, resourceID string, authorized bool, httpVerb string) (AuthorizeResult, error) {
	if httpVerb == "" {
		httpVerb = "PUT"
	}
	payload := map[string]any{"subject": subject, "resource_id": resourceID, "authorized": authorized, "http_verb": httpVerb}
	return c.postAuthorize(ctx, payload, authorized)
}

// AuthorizeOrError is a convenience wrapper: it calls Authorize and returns a
// *BlockedError (checkable with errors.As) if the decision is "block". On
// "allow" or "deny" it returns the result with a nil error - checking
// result.Decision == DecisionDeny is on you.
func (c *Client) AuthorizeOrError(ctx context.Context, subject, resourceID string, authorized bool) (AuthorizeResult, error) {
	result, err := c.Authorize(ctx, subject, resourceID, authorized)
	if err != nil {
		return result, err
	}
	if result.Blocked() {
		return result, &BlockedError{Result: result}
	}
	return result, nil
}

// AuthorizeBatch evaluates an array of resource requests with atomic batch
// limits and mid-batch blocking.
func (c *Client) AuthorizeBatch(ctx context.Context, subject string, items []BatchItem) (BatchResult, error) {
	payload := map[string]any{"subject": subject, "items": items}
	var result BatchResult
	err := c.postJSON(ctx, "/v1/authorize-batch", payload, &result)
	if err == nil {
		return result, nil
	}
	if errors.Is(err, ErrInvalidAPIKey) {
		return BatchResult{}, err
	}
	return c.batchFallback(items), nil
}

func (c *Client) batchFallback(items []BatchItem) BatchResult {
	results := make([]BatchResultItem, len(items))
	for i, item := range items {
		decision := DecisionDeny
		if c.failOpen && item.Authorized {
			decision = DecisionAllow
		}
		results[i] = BatchResultItem{ResourceID: item.ResourceID, Decision: decision, Score: 0, Signals: nil}
	}
	return BatchResult{Total: len(items), BlockedMidBatch: false, Results: results}
}

func (c *Client) postAuthorize(ctx context.Context, payload map[string]any, authorized bool) (AuthorizeResult, error) {
	var result AuthorizeResult
	err := c.postJSON(ctx, "/v1/authorize", payload, &result)
	if err == nil {
		return result, nil
	}
	if errors.Is(err, ErrInvalidAPIKey) {
		return AuthorizeResult{}, err
	}
	return c.fallback(authorized), nil
}

// fallback never returns DecisionBlock: a block reflects a genuine
// behavioral-risk finding from the engine, not a network failure.
func (c *Client) fallback(authorized bool) AuthorizeResult {
	if c.failOpen {
		decision := DecisionDeny
		if authorized {
			decision = DecisionAllow
		}
		return AuthorizeResult{Decision: decision, Score: 0, Category: "Unknown",
			Explanations: []string{"CyberAccess API unreachable - failed open"}}
	}
	return AuthorizeResult{Decision: DecisionDeny, Score: 0, Category: "Unknown",
		Explanations: []string{"CyberAccess API unreachable - failed closed"}}
}

// postJSON returns ErrInvalidAPIKey on a 401 response (never falls back for
// that case - it's a caller misconfiguration, not a transient outage), and a
// plain error for any other transport/decode failure (which callers here
// treat as "unreachable" and route to the fail-open/fail-closed fallback).
func (c *Client) postJSON(ctx context.Context, path string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrInvalidAPIKey
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cyberaccess: API returned %d: %s", resp.StatusCode, string(respBody))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
