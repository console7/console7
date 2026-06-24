package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// fakeTokenSource is a hermetic stand-in for ADC: it returns a fixed token, or an
// error to exercise the fail-closed path. No GCP, no metadata server, no network.
type fakeTokenSource struct {
	token string
	err   error
}

func (f fakeTokenSource) Token() (*oauth2.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &oauth2.Token{AccessToken: f.token, TokenType: "Bearer"}, nil
}

// capture records what the fake upstream Vertex host received, so the test can assert
// the path rewrite, the injected bearer, the method, and the body.
type capture struct {
	method string
	path   string
	auth   string
	body   string
	hdr    http.Header
}

// newFakeUpstream returns an httptest server that records the request and replies
// with a canned body, plus the parsed *url.URL to hand to newAuthProxy.
func newFakeUpstream(t *testing.T, got *capture, reply string) (*httptest.Server, *url.URL) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.path = r.URL.Path
		got.auth = r.Header.Get("Authorization")
		got.body = string(b)
		got.hdr = r.Header.Clone()
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	return srv, u
}

// TestForwards_PrefixesV1_AddsBearer_PreservesMethodBody asserts the happy path:
// (a) the path gains the /v1 prefix the engine omits, (b) a Bearer from the injected
// token source is attached, (c) method + body + anthropic-*/content-type headers are
// forwarded verbatim.
func TestForwards_PrefixesV1_AddsBearer_PreservesMethodBody(t *testing.T) {
	var got capture
	_, upstream := newFakeUpstream(t, &got, `{"ok":true}`)

	ap, err := newAuthProxy(upstream, fakeTokenSource{token: "fake-access-token"})
	if err != nil {
		t.Fatalf("newAuthProxy: %v", err)
	}
	front := httptest.NewServer(ap)
	t.Cleanup(front.Close)

	// The engine sends this path with NO /v1 prefix and NO Authorization header.
	enginePath := "/projects/p1/locations/us-central1/publishers/anthropic/models/claude-x:rawPredict"
	reqBody := `{"messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest(http.MethodPost, front.URL+enginePath, strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "messages-2023")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	if got.method != http.MethodPost {
		t.Errorf("method: got %q want POST", got.method)
	}
	if want := "/v1" + enginePath; got.path != want {
		t.Errorf("path: got %q want %q (the proxy must prepend /v1)", got.path, want)
	}
	if got.auth != "Bearer fake-access-token" {
		t.Errorf("authorization: got %q want %q", got.auth, "Bearer fake-access-token")
	}
	if got.body != reqBody {
		t.Errorf("body: got %q want %q", got.body, reqBody)
	}
	if got.hdr.Get("anthropic-version") != "2023-06-01" {
		t.Errorf("anthropic-version header not preserved: %q", got.hdr.Get("anthropic-version"))
	}
	if got.hdr.Get("anthropic-beta") != "messages-2023" {
		t.Errorf("anthropic-beta header not preserved: %q", got.hdr.Get("anthropic-beta"))
	}
	if got.hdr.Get("Content-Type") != "application/json" {
		t.Errorf("content-type not preserved: %q", got.hdr.Get("Content-Type"))
	}
	if string(respBody) != `{"ok":true}` {
		t.Errorf("response body not streamed back: %q", string(respBody))
	}
}

// TestStreamRawPredict_PathRewrite asserts :streamRawPredict is rewritten identically
// (SSE streaming itself is the reverse proxy's default; here we assert the path).
func TestStreamRawPredict_PathRewrite(t *testing.T) {
	var got capture
	_, upstream := newFakeUpstream(t, &got, "data: {}\n\n")

	ap, err := newAuthProxy(upstream, fakeTokenSource{token: "tok"})
	if err != nil {
		t.Fatalf("newAuthProxy: %v", err)
	}
	front := httptest.NewServer(ap)
	t.Cleanup(front.Close)

	enginePath := "/projects/p/locations/global/publishers/anthropic/models/m:streamRawPredict"
	resp, err := http.Post(front.URL+enginePath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()

	if want := "/v1" + enginePath; got.path != want {
		t.Errorf("path: got %q want %q", got.path, want)
	}
}

// TestFailsClosed_OnTokenError asserts the SECURITY invariant: when the token source
// errors, the proxy returns 503 and NEVER forwards to the upstream.
func TestFailsClosed_OnTokenError(t *testing.T) {
	var got capture
	forwarded := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		got.path = r.URL.Path
	}))
	t.Cleanup(srv.Close)
	upstream, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ap, err := newAuthProxy(upstream, fakeTokenSource{err: errors.New("metadata server unavailable")})
	if err != nil {
		t.Fatalf("newAuthProxy: %v", err)
	}
	front := httptest.NewServer(ap)
	t.Cleanup(front.Close)

	resp, err := http.Post(front.URL+"/projects/p/locations/us-central1/publishers/anthropic/models/m:rawPredict",
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: got %d want 503 (fail closed)", resp.StatusCode)
	}
	if forwarded {
		t.Errorf("SECURITY: request was forwarded to upstream despite token failure (path=%q)", got.path)
	}
}

// TestFailsClosed_OnEmptyToken asserts an empty access token is treated as a token
// failure (fail closed), not forwarded with an empty Bearer.
func TestFailsClosed_OnEmptyToken(t *testing.T) {
	forwarded := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded = true }))
	t.Cleanup(srv.Close)
	upstream, _ := url.Parse(srv.URL)

	ap, err := newAuthProxy(upstream, fakeTokenSource{token: ""})
	if err != nil {
		t.Fatalf("newAuthProxy: %v", err)
	}
	front := httptest.NewServer(ap)
	t.Cleanup(front.Close)

	resp, err := http.Post(front.URL+"/x:rawPredict", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: got %d want 503", resp.StatusCode)
	}
	if forwarded {
		t.Errorf("SECURITY: forwarded with empty token")
	}
}

func TestWithV1Prefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/projects/p/locations/r/publishers/anthropic/models/m:rawPredict", "/v1/projects/p/locations/r/publishers/anthropic/models/m:rawPredict"},
		{"projects/p:rawPredict", "/v1/projects/p:rawPredict"}, // missing leading slash
		{"/v1/already", "/v1/already"},                         // idempotent — no double prefix
		{"/v1", "/v1"},                                         // exact /v1 unchanged
		{"/v1foo", "/v1/v1foo"},                                // /v1foo is NOT the /v1 segment
	}
	for _, c := range cases {
		if got := withV1Prefix(c.in); got != c.want {
			t.Errorf("withV1Prefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveUpstream(t *testing.T) {
	t.Run("region", func(t *testing.T) {
		u, err := resolveUpstream("", "us-central1")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if u.String() != "https://us-central1-aiplatform.googleapis.com" {
			t.Errorf("got %q", u.String())
		}
	})
	t.Run("global", func(t *testing.T) {
		u, err := resolveUpstream("", "global")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if u.String() != "https://aiplatform.googleapis.com" {
			t.Errorf("got %q", u.String())
		}
	})
	t.Run("override wins and is normalised to scheme+host", func(t *testing.T) {
		u, err := resolveUpstream("https://example-vertex.internal/ignored/path", "us-central1")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if u.String() != "https://example-vertex.internal" {
			t.Errorf("got %q", u.String())
		}
	})
	t.Run("override must be https", func(t *testing.T) {
		if _, err := resolveUpstream("http://nope.internal", ""); err == nil {
			t.Error("expected error for non-https override")
		}
	})
	t.Run("empty region without override errors", func(t *testing.T) {
		if _, err := resolveUpstream("", ""); err == nil {
			t.Error("expected error for empty region")
		}
	})
	t.Run("region with host-smuggling chars rejected", func(t *testing.T) {
		for _, bad := range []string{"us-central1/evil", "evil.com", "a:b", "x@y"} {
			if _, err := resolveUpstream("", bad); err == nil {
				t.Errorf("expected error for region %q", bad)
			}
		}
	})
}

func TestNewAuthProxy_NilArgs(t *testing.T) {
	u, _ := url.Parse("https://x-aiplatform.googleapis.com")
	if _, err := newAuthProxy(nil, fakeTokenSource{token: "t"}); err == nil {
		t.Error("expected error for nil upstream")
	}
	if _, err := newAuthProxy(u, nil); err == nil {
		t.Error("expected error for nil token source")
	}
}

// TestFileTokenSource covers the DELIVERED-FILE token mode (the per-session deployment): read the
// bearer from the file on each call (so a re-delivered/rotated token is picked up), trim whitespace,
// set no Expiry, and fail closed on a missing or empty file (the handler turns that into a 503).
func TestFileTokenSource(t *testing.T) {
	p := filepath.Join(t.TempDir(), "credential")
	fts := fileTokenSource{path: p}

	if _, err := fts.Token(); err == nil {
		t.Error("missing file: want error (fail closed), got nil")
	}

	if err := os.WriteFile(p, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	if _, err := fts.Token(); err == nil {
		t.Error("empty file: want error, got nil")
	}

	if err := os.WriteFile(p, []byte("  tok-abc\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	tok, err := fts.Token()
	if err != nil {
		t.Fatalf("valid file: unexpected err %v", err)
	}
	if tok.AccessToken != "tok-abc" {
		t.Errorf("AccessToken = %q, want %q (trimmed)", tok.AccessToken, "tok-abc")
	}
	if !tok.Expiry.IsZero() {
		t.Errorf("Expiry = %v, want zero (freshness via re-delivery, not oauth2 refresh)", tok.Expiry)
	}

	// A re-delivered (rotated) token is picked up on the next call — no caching, no restart.
	if err := os.WriteFile(p, []byte("tok-rotated"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	tok2, err := fts.Token()
	if err != nil {
		t.Fatalf("rotated file: unexpected err %v", err)
	}
	if tok2.AccessToken != "tok-rotated" {
		t.Errorf("after rotation AccessToken = %q, want %q", tok2.AccessToken, "tok-rotated")
	}
}

// TestSelectTokenSource_FileMode covers the deterministic, no-network branch: a non-empty bearer-file
// path selects the delivered-file source and reports the file mode. (The ambient-ADC branch needs a
// real metadata server, so it is exercised in deployment, not here.)
func TestSelectTokenSource_FileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(p, []byte("tok-xyz"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ts, mode, err := selectTokenSource(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected err %v", err)
	}
	if _, ok := ts.(fileTokenSource); !ok {
		t.Errorf("source type = %T, want fileTokenSource", ts)
	}
	if !strings.Contains(mode, "delivered bearer file") {
		t.Errorf("mode = %q, want it to mention the delivered bearer file", mode)
	}
	tok, err := ts.Token()
	if err != nil || tok.AccessToken != "tok-xyz" {
		t.Errorf("Token() = (%v, %v), want tok-xyz", tok, err)
	}
}
