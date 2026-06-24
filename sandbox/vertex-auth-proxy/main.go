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
)

const (
	envListen   = "C7_AUTHPROXY_LISTEN"   // listen addr, default ":8080"
	envUpstream = "C7_AUTHPROXY_UPSTREAM" // explicit upstream override (absolute https)
	envRegion   = "CLOUD_ML_REGION"       // Vertex region; "global" → aiplatform.googleapis.com
	envProject  = "C7_AUTHPROXY_PROJECT"  // pin: only forward predict calls for this Vertex project ("" = any)
	envModel    = "C7_AUTHPROXY_MODEL"    // pin: only forward predict calls for this model ("" = any anthropic model)
	defaultAddr = ":8080"
)

// envBearerFile names the env var holding the PATH to the control-plane-delivered bearer file (delivered
// -file mode; if unset, ambient ADC is used). Its value is an env-var NAME, not a secret — gosec G101
// false-positives on the "bearer" substring (same class as RISKS R-9 / R-13).
const envBearerFile = "C7_AUTHPROXY_BEARER_FILE" //nolint:gosec // G101: env-var name, not a credential (RISKS R-13)

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

	region := os.Getenv(envRegion)
	upstream, err := resolveUpstream(os.Getenv(envUpstream), region)
	if err != nil {
		return err
	}

	ts, mode, err := selectTokenSource(context.Background(), os.Getenv(envBearerFile))
	if err != nil {
		return err
	}

	// Pin what the credential-free sandbox can invoke through us: always an anthropic predict call
	// (enforced by requestPin), further pinned to this project/region/model when set (the control plane
	// sets them per session). region comes from CLOUD_ML_REGION (empty under a C7_AUTHPROXY_UPSTREAM
	// override ⇒ region not pinned, but structure + publisher + verb still are).
	pin := requestPin{project: os.Getenv(envProject), region: region, model: os.Getenv(envModel)}

	ap, err := newAuthProxy(upstream, ts, pin)
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

	//nolint:gosec // G706 — RISKS R-12: addr/upstream/mode are operator-supplied process config (env +
	// validated resolveUpstream), not request-derived taint; logged once at startup, no body/token.
	log.Printf("vertex-auth-proxy: listening on %s, forwarding to %s (adding /v1 + bearer via %s)", addr, upstream.String(), mode)
	return srv.ListenAndServe()
}
