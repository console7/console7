// Command vertex-auth-proxy runs the Console7 Vertex auth-proxy (see proxy.go for the
// trust-tier rationale and the engine contract it bridges).
//
// It is a thin main: parse config from the environment, build the ADC-backed token
// source, construct the handler, and serve. All behaviour worth testing lives in
// proxy.go and is covered hermetically (proxy_test.go) with a fake token source —
// this file performs only ambient ADC wiring and process lifecycle, which need a real
// metadata server / GCP and are therefore exercised in deployment, not unit tests.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	envListen   = "C7_AUTHPROXY_LISTEN"   // listen addr, default ":8080"
	envUpstream = "C7_AUTHPROXY_UPSTREAM" // explicit upstream override (absolute https)
	envRegion   = "CLOUD_ML_REGION"       // Vertex region; "global" → aiplatform.googleapis.com
	defaultAddr = ":8080"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("vertex-auth-proxy: %v", err)
	}
}

func run() error {
	addr := os.Getenv(envListen)
	if addr == "" {
		addr = defaultAddr
	}

	upstream, err := resolveUpstream(os.Getenv(envUpstream), os.Getenv(envRegion))
	if err != nil {
		return err
	}

	// AMBIENT ADC: the pod's OWN Workload Identity, reached via the metadata server.
	// DefaultTokenSource caches + refreshes the token internally, so the per-request
	// Token() call is cheap and always returns a currently-valid token (or an error,
	// which the handler turns into a fail-closed 503). We construct it eagerly so a
	// misconfigured environment fails at startup, not on the first request.
	ts, err := google.DefaultTokenSource(context.Background(), cloudPlatformScope)
	if err != nil {
		return err
	}

	ap, err := newAuthProxy(upstream, oauth2.ReuseTokenSource(nil, ts))
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: ap,
		// Conservative timeouts. ReadHeaderTimeout guards Slowloris; WriteTimeout is
		// generous because streamRawPredict responses (SSE) can be long-lived, but is
		// bounded so a wedged upstream cannot pin a connection forever.
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      0, // 0 = no write deadline: required for long SSE streams.
		IdleTimeout:       120 * time.Second,
	}

	//nolint:gosec // G706 — RISKS R-12: addr/upstream are operator-supplied process config (env +
	// validated resolveUpstream), not request-derived taint; logged once at startup, no body/token.
	log.Printf("vertex-auth-proxy: listening on %s, forwarding to %s (adding /v1 + ambient bearer)", addr, upstream.String())
	return srv.ListenAndServe()
}
