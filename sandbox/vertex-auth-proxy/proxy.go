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
// proxy is what closes that gap: it accepts the credential-free request, validates it is a permitted
// (pinned) Vertex predict call, adds the `/v1` prefix and a Google bearer, and streams the upstream
// response back.
//
// WHERE THE BEARER COMES FROM (deployment modes — see selectTokenSource): the PRIMARY, what-this-repo-runs
// mode is DELIVERED-FILE — deploy/ is google-provider-only with NO persistent in-cluster workload, so this
// proxy holds NO Workload Identity; the control plane mints the short-lived Vertex bearer (workload-SA
// self-impersonation) and DELIVERS it (per session) into this pod's token file (C7_AUTHPROXY_BEARER_FILE),
// in a pod SEPARATE from the untrusted sandbox. Ambient Workload Identity is a SECONDARY mode kept for a
// future persistent/shared deployment that does not yet exist.
//
// TRUST TIER (ARCHITECTURE.md §6.4): this artifact HOLDS A CREDENTIAL — it attaches a cloud-platform
// Google access token. It is therefore a CONTROL-side / credentialed data-plane artifact and MUST NOT
// share a build identity with the untrusted sandbox base image (which stays metadata-/credential-free).
// It ships as a DISTINCT, separately-signed image (auth-proxy-image-release.yml).
//
// SECURITY invariants enforced here:
//   - PIN (anti-open-relay): only an anthropic-publisher Vertex predict call for the configured
//     project/region/model is forwarded; anything else is 404'd with the bearer NEVER attached.
//   - Fail closed: if no token is available, return 503 and NEVER forward the request unauthenticated.
//     An upstream that 401s and an upstream reached without a token are not the same failure; we never
//     produce the latter.
//   - Never log token material, request/response bodies, or request-derived paths.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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

// fileTokenSource reads a bearer access token from a file on EACH call. In the
// per-session deployment (the only model this repo can run — there is no persistent
// in-cluster workload, so the proxy cannot hold its own Workload Identity), the
// control plane MINTS the short-lived Vertex bearer (workload-SA self-impersonation)
// and DELIVERS it into this proxy pod's token file, separate from the untrusted
// sandbox pod. Re-reading per request means a re-delivered (refreshed) token is picked
// up with no restart; we deliberately do NOT cache (a stale token would outlive a
// rotation) and set NO Expiry (this is a pure consumer — there is no refresh token, so
// freshness comes from re-delivery, not oauth2 refresh). Fail closed: a missing or
// empty file returns an error, which the handler turns into a 503.
type fileTokenSource struct{ path string }

func (f fileTokenSource) Token() (*oauth2.Token, error) {
	b, err := os.ReadFile(f.path) //nolint:gosec // G304: path is operator-supplied process config (the
	// delivered-bearer file path), not request-derived taint; the proxy reads only this configured file.
	if err != nil {
		return nil, fmt.Errorf("read delivered token file: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return nil, errors.New("delivered token file is empty")
	}
	return &oauth2.Token{AccessToken: tok}, nil
}

// selectTokenSource picks where the Google bearer comes from, by deployment mode:
//   - bearerFile != "" ⇒ DELIVERED-FILE mode (the per-session deployment this repo runs: there is NO
//     persistent in-cluster workload, so the proxy holds no Workload Identity; the control plane mints
//     the short-lived Vertex bearer and delivers it into this pod's token file, separate from the
//     untrusted sandbox pod). Re-read per request so a re-delivered token is picked up.
//   - else ⇒ AMBIENT ADC mode (the pod's own Workload Identity via the metadata server; for a future
//     persistent/shared deployment). DefaultTokenSource caches+refreshes internally; built eagerly here
//     so a misconfigured environment fails at startup, not on the first request.
//
// It returns the source and a human-readable mode label for the startup log (never the token).
func selectTokenSource(ctx context.Context, bearerFile string) (tokenSource, string, error) {
	if bearerFile != "" {
		return fileTokenSource{path: bearerFile}, "delivered bearer file " + bearerFile, nil
	}
	adc, err := google.DefaultTokenSource(ctx, cloudPlatformScope)
	if err != nil {
		return nil, "", err
	}
	return oauth2.ReuseTokenSource(nil, adc), "ambient ADC", nil
}

// predictPathRE matches the ONLY request shape the engine sends and the ONLY one this proxy will attach
// a bearer to: an Anthropic-publisher Vertex predict call (rawPredict | streamRawPredict), pre-`/v1`.
// Anchored + single-segment captures so it cannot be widened with extra path segments.
var predictPathRE = regexp.MustCompile(`^/projects/([^/]+)/locations/([^/]+)/publishers/anthropic/models/([^/:]+):(rawPredict|streamRawPredict)$`)

// requestPin bounds what the credential-free sandbox can invoke THROUGH this proxy. Every request must
// match predictPathRE (structure + publisher=anthropic + a predict verb); project/region/model further
// pin it when set ("" = do not pin that field — e.g. region is empty under a C7_AUTHPROXY_UPSTREAM
// override). This stops the proxy being an OPEN RELAY that attaches the org Vertex bearer to arbitrary
// Vertex APIs — least privilege (GOAL.md tenet 4), defence-in-depth atop the predict-only IAM role on
// the minting SA. A non-matching request is rejected (404) with the bearer NEVER attached.
type requestPin struct {
	project string // ANTHROPIC_VERTEX_PROJECT_ID the session is pinned to ("" = any)
	region  string // CLOUD_ML_REGION ("global" for the global host; "" = any, e.g. upstream override)
	model   string // the pinned model ("" = any anthropic model)
}

func (p requestPin) allow(path string) bool {
	m := predictPathRE.FindStringSubmatch(path)
	if m == nil {
		return false
	}
	proj, region, model := m[1], m[2], m[3]
	if p.project != "" && proj != p.project {
		return false
	}
	if p.region != "" && region != p.region {
		return false
	}
	if p.model != "" && model != p.model {
		return false
	}
	return true
}

// authProxy is the credential-attaching reverse proxy handler.
type authProxy struct {
	// upstream is the validated absolute https base of the real Vertex host, e.g.
	// https://us-central1-aiplatform.googleapis.com (NO /v1 — the proxy adds it).
	upstream *url.URL
	// tokens mints the Google bearer attached to each forwarded request.
	tokens tokenSource
	// pin bounds which Vertex calls may be forwarded (anti-open-relay; see requestPin).
	pin requestPin
	// rp is the underlying streaming reverse proxy (httputil.ReverseProxy streams by
	// default — it does NOT buffer the whole body — so SSE for :streamRawPredict works).
	rp *httputil.ReverseProxy
}

// newAuthProxy wires a streaming reverse proxy to upstream, minting+attaching a bearer on every
// (pinned) request via tokens. upstream MUST be an absolute https URL.
func newAuthProxy(upstream *url.URL, tokens tokenSource, pin requestPin) (*authProxy, error) {
	if upstream == nil {
		return nil, errors.New("vertex-auth-proxy: nil upstream")
	}
	if tokens == nil {
		return nil, errors.New("vertex-auth-proxy: nil token source")
	}
	ap := &authProxy{upstream: upstream, tokens: tokens, pin: pin}

	ap.rp = &httputil.ReverseProxy{
		// Rewrite (NOT Director): with Rewrite, ReverseProxy does NOT auto-append an
		// X-Forwarded-For — so the "we add nothing" invariant actually holds. Token mint, path
		// rewrite, and the pin check all happen in ServeHTTP BEFORE the request reaches rp, so a
		// rejected/credential-less request fails closed (Rewrite cannot signal an error).
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(ap.upstream)         // scheme+host; upstream has no path, so the /v1 path is preserved
			pr.Out.Host = ap.upstream.Host // Host header / SNI = the real Vertex host
			// Strip any inbound forwarding headers a hostile caller could set; we deliberately do
			// NOT call pr.SetXForwarded(), so none are added back.
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
				pr.Out.Header.Del(h)
			}
		},
		// Stream SSE immediately rather than buffering (FlushInterval -1 = flush each write).
		// rawPredict is unary; streamRawPredict is SSE — both are safe to flush.
		FlushInterval: -1,
		// Bound the connect + time-to-first-byte so a wedged/hostile upstream cannot pin a
		// connection forever; the STREAM body stays unbounded (no response deadline) for SSE.
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment, // honour HTTPS_PROXY if egress is routed via the per-session proxy
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          10,
		},
		ErrorLog: log.Default(),
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
	// 1. PIN check FIRST — before minting or attaching anything. Only an Anthropic-publisher Vertex
	// predict call for the pinned project/region/model may be forwarded; anything else is rejected with
	// the bearer NEVER attached, so the proxy is not an open relay for the credential-free sandbox.
	if !ap.pin.allow(r.URL.Path) {
		// Do NOT log the request-derived path (log-injection taint); the security event — a request
		// that is not a permitted, pinned Vertex predict call — is what matters.
		log.Printf("vertex-auth-proxy: rejected a request that is not a permitted Vertex predict call (pin)")
		http.Error(w, "vertex-auth-proxy: request not permitted", http.StatusNotFound)
		return
	}

	// 2. Mint the token. If we cannot, fail closed with 503 and forward NOTHING.
	tok, err := ap.tokens.Token()
	if err != nil || tok == nil || tok.AccessToken == "" {
		// Do not log the error object verbatim if it could carry token material; the
		// oauth2 errors are safe, but we keep the line generic regardless.
		log.Printf("vertex-auth-proxy: token mint failed; failing closed (503)")
		http.Error(w, "vertex-auth-proxy: upstream credential unavailable", http.StatusServiceUnavailable)
		return
	}

	// 3. Rewrite the path: the engine omits `/v1` when the base URL is overridden, so
	// the real Vertex host (which serves under /v1) needs it prepended. Done once,
	// idempotently — never double-prefix if a future engine starts sending it. Clear
	// RawPath so the rewritten (unescaped) Path is authoritative on re-encode — a stale
	// RawPath would otherwise be emitted verbatim and bypass the prefix.
	r.URL.Path = withV1Prefix(r.URL.Path)
	r.URL.RawPath = ""

	// 4. Attach the bearer. tok.SetAuthHeader sets `Authorization: Bearer <token>`
	// (honouring the token type). We overwrite any inbound Authorization (the engine
	// sends none, but we are authoritative).
	tok.SetAuthHeader(r)

	// 5. Forward (streaming). The reverse proxy preserves method, body, and the
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
