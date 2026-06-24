// Package main is the Console7 Vertex auth-proxy: a tiny, single-purpose reverse
// proxy that sits between the (credential-free) sandbox and a real Vertex AI host.
//
// WHY THIS EXISTS (verified against the pinned Claude Code engine @1.0.44): when the
// engine is pointed at a custom Vertex base URL via
//
//	CLAUDE_CODE_SKIP_VERTEX_AUTH=1
//	ANTHROPIC_VERTEX_BASE_URL=http://<this-proxy>
//
// it emits Vertex rawPredict/streamRawPredict requests with NO Google Authorization
// header and, critically, with NO `/v1` prefix on the path (the engine only adds
// `/v1` for its built-in `https://{region}-aiplatform.googleapis.com/v1` host). This
// proxy is what closes that gap: it accepts the credential-free request, adds the
// `/v1` prefix and a freshly-minted Google bearer token (from the pod's OWN ambient
// Workload Identity), and streams the upstream response back.
//
// TRUST TIER (ARCHITECTURE.md §6.4): this artifact HOLDS A CREDENTIAL — it mints and
// attaches a cloud-platform Google access token. It is therefore a CONTROL-side /
// credentialed data-plane artifact and MUST NOT share a build identity with the
// untrusted sandbox base image (which stays metadata-/credential-free). It ships as
// a DISTINCT, separately-signed image (auth-proxy-image-release.yml).
//
// SECURITY invariants enforced here:
//   - Fail closed: if no token can be minted, return 503 and NEVER forward the
//     request unauthenticated. An upstream that 401s and an upstream that is reached
//     without a token are not the same failure; we never produce the latter.
//   - Never log token material or request/response bodies.
package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// cloudPlatformScope is the OAuth scope the minted token carries. Vertex AI
// (aiplatform.googleapis.com) is reached under the broad cloud-platform scope; the
// EFFECTIVE authority is bounded by the pod's Workload Identity IAM role, not by this
// scope (least privilege is a deploy-time concern — F2b: bind a GSA with only the
// Vertex predict role).
const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// tokenSource abstracts where the Google bearer comes from so the handler is unit-
// testable with a fake (no GCP, no metadata server, no network). The real
// implementation is backed by golang.org/x/oauth2/google.DefaultTokenSource, which
// reads AMBIENT ADC (the pod's Workload Identity via the metadata server) and
// caches+refreshes the token internally.
type tokenSource interface {
	// Token returns a currently-valid access token, or an error. On error the
	// handler MUST fail closed (it must never forward unauthenticated).
	Token() (*oauth2.Token, error)
}

// authProxy is the credential-attaching reverse proxy handler.
type authProxy struct {
	// upstream is the validated absolute https base of the real Vertex host, e.g.
	// https://us-central1-aiplatform.googleapis.com (NO /v1 — the proxy adds it).
	upstream *url.URL
	// tokens mints the Google bearer attached to each forwarded request.
	tokens tokenSource
	// rp is the underlying streaming reverse proxy (httputil.ReverseProxy streams by
	// default — it does NOT buffer the whole body — so SSE for :streamRawPredict works).
	rp *httputil.ReverseProxy
}

// newAuthProxy wires a streaming reverse proxy to upstream, minting+attaching a
// bearer on every request via tokens. upstream MUST be an absolute https URL.
func newAuthProxy(upstream *url.URL, tokens tokenSource) (*authProxy, error) {
	if upstream == nil {
		return nil, errors.New("vertex-auth-proxy: nil upstream")
	}
	if tokens == nil {
		return nil, errors.New("vertex-auth-proxy: nil token source")
	}
	ap := &authProxy{upstream: upstream, tokens: tokens}

	ap.rp = &httputil.ReverseProxy{
		// Director sets the upstream host. Token minting and path rewriting happen in
		// ServeHTTP BEFORE the request is handed to rp, so that a token error can fail
		// closed (the Director cannot return an error). FlushInterval defaults to
		// streaming for text/event-stream responses, so SSE is not buffered.
		Director: func(r *http.Request) {
			r.URL.Scheme = ap.upstream.Scheme
			r.URL.Host = ap.upstream.Host
			r.Host = ap.upstream.Host
			// Strip any inbound Forwarded/X-Forwarded-* the engine never sets but a
			// hostile target could; we are the authoritative front and add nothing.
			r.Header.Del("X-Forwarded-For")
			r.Header.Del("Forwarded")
		},
		// Stream SSE immediately rather than buffering (FlushInterval -1 = flush each
		// write). rawPredict is unary; streamRawPredict is SSE — both are safe to flush.
		FlushInterval: -1,
		ErrorLog:      log.Default(),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			// Never echo the error detail to the client (could leak upstream URL
			// internals); log a generic line with no body/token material.
			log.Printf("vertex-auth-proxy: upstream error: %v", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return ap, nil
}

// ServeHTTP mints a token (fail-closed), rewrites the path to add the `/v1` prefix
// the engine omits under a base-URL override, attaches the bearer, and streams the
// request to the real Vertex host.
func (ap *authProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Mint the token FIRST. If we cannot, fail closed with 503 and forward NOTHING.
	tok, err := ap.tokens.Token()
	if err != nil || tok == nil || tok.AccessToken == "" {
		// Do not log the error object verbatim if it could carry token material; the
		// oauth2 errors are safe, but we keep the line generic regardless.
		log.Printf("vertex-auth-proxy: token mint failed; failing closed (503)")
		http.Error(w, "vertex-auth-proxy: upstream credential unavailable", http.StatusServiceUnavailable)
		return
	}

	// 2. Rewrite the path: the engine omits `/v1` when the base URL is overridden, so
	// the real Vertex host (which serves under /v1) needs it prepended. Done once,
	// idempotently — never double-prefix if a future engine starts sending it. Clear
	// RawPath so the rewritten (unescaped) Path is authoritative on re-encode — a stale
	// RawPath would otherwise be emitted verbatim and bypass the prefix.
	r.URL.Path = withV1Prefix(r.URL.Path)
	r.URL.RawPath = ""

	// 3. Attach the bearer. tok.SetAuthHeader sets `Authorization: Bearer <token>`
	// (honouring the token type). We overwrite any inbound Authorization (the engine
	// sends none, but we are authoritative).
	tok.SetAuthHeader(r)

	// 4. Forward (streaming). The reverse proxy preserves method, body, and the
	// anthropic-* / content-type headers as-is.
	ap.rp.ServeHTTP(w, r)
}

// withV1Prefix prepends `/v1` to an engine-supplied path, idempotently. The engine
// sends e.g. `/projects/{p}/locations/{r}/publishers/anthropic/models/{m}:rawPredict`
// (no leading version segment); the real host serves it under `/v1/...`.
func withV1Prefix(p string) string {
	if p == "/v1" || strings.HasPrefix(p, "/v1/") {
		return p // already prefixed — do not double it
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "/v1" + p
}

// resolveUpstream derives the upstream Vertex base URL from configuration. Precedence:
//   - explicit C7_AUTHPROXY_UPSTREAM override (must be an absolute https URL), else
//   - CLOUD_ML_REGION → https://{region}-aiplatform.googleapis.com, with the special
//     value "global" → https://aiplatform.googleapis.com (the location-agnostic host).
//
// The returned URL carries NO path (no /v1); the handler adds /v1 per request.
func resolveUpstream(override, region string) (*url.URL, error) {
	if override != "" {
		u, err := url.Parse(override)
		if err != nil {
			return nil, fmt.Errorf("C7_AUTHPROXY_UPSTREAM %q: %w", override, err)
		}
		if u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("C7_AUTHPROXY_UPSTREAM must be an absolute https URL, got %q", override)
		}
		// Normalise: keep only scheme+host; per-request path is added by the handler.
		return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
	}
	region = strings.TrimSpace(region)
	if region == "" {
		return nil, errors.New("CLOUD_ML_REGION is required (or set C7_AUTHPROXY_UPSTREAM)")
	}
	if region == "global" {
		return &url.URL{Scheme: "https", Host: "aiplatform.googleapis.com"}, nil
	}
	// A region is a single DNS label segment; reject anything that could smuggle a
	// host (slashes, dots) so the upstream host cannot be redirected via config.
	if strings.ContainsAny(region, "/.:@ ") {
		return nil, fmt.Errorf("CLOUD_ML_REGION %q is not a valid region label", region)
	}
	return &url.URL{Scheme: "https", Host: region + "-aiplatform.googleapis.com"}, nil
}
