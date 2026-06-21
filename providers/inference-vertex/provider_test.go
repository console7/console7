package inferencevertex

import (
	"context"
	"strings"
	"testing"

	"github.com/console7/console7/sdk/interfaces"
)

func mustNew(t *testing.T, cfg Config) *Provider {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New(%+v): %v", cfg, err)
	}
	return p
}

// TestResolve_Seam exercises the routing decision against the SECURITY contract in
// sdk/interfaces/inference.go: fail-closed modes, the unconditional subscription refusal
// (Vertex-specific), and the org-API route to the resolved Vertex host.
func TestResolve_Seam(t *testing.T) {
	const region = "us-east5"
	regionalHost := "https://" + region + "-aiplatform.googleapis.com"
	regional := Config{ProjectID: "p", Region: region}

	sub := func(attended bool, beneficiaries int) interfaces.InferenceSelection {
		return interfaces.InferenceSelection{
			SessionID: "s1", Subject: "sso|alice",
			Mode: interfaces.ModeSubscription, Attended: attended, Beneficiaries: beneficiaries,
		}
	}

	tests := []struct {
		name    string
		cfg     Config
		sel     interfaces.InferenceSelection
		wantErr bool
		wantURL string
	}{
		// Fail-closed mode handling.
		{name: "unspecified mode fails closed", cfg: regional, sel: interfaces.InferenceSelection{Attended: true, Beneficiaries: 1}, wantErr: true},
		{name: "unrecognised mode fails closed", cfg: regional, sel: interfaces.InferenceSelection{Mode: interfaces.InferenceMode(99), Attended: true, Beneficiaries: 1}, wantErr: true},

		// Subscription is refused unconditionally — even the attended single-beneficiary case
		// the Anthropic backend would serve. Never a downgrade to org-API.
		{name: "subscription refused — attended single beneficiary", cfg: regional, sel: sub(true, 1), wantErr: true},
		{name: "subscription refused — unattended", cfg: regional, sel: sub(false, 1), wantErr: true},
		{name: "subscription refused — multi-beneficiary fan-out", cfg: regional, sel: sub(true, 2), wantErr: true},

		// Org-API route → the resolved in-tenancy Vertex host.
		{name: "org-api regional host", cfg: regional, sel: interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI}, wantURL: regionalHost},
		{name: "org-api global host", cfg: Config{ProjectID: "p", Global: true}, sel: interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI}, wantURL: GlobalHost},
		{name: "org-api PSC override", cfg: Config{ProjectID: "p", Region: region, EndpointBaseURL: "https://us-east5-aiplatform.vpc.p.googleapis.com"}, sel: interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI}, wantURL: "https://us-east5-aiplatform.vpc.p.googleapis.com"},
		// An unattended / fan-out session on the org-API route is fine (that is the point).
		{name: "org-api unattended fan-out ok", cfg: regional, sel: interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI, Attended: false, Beneficiaries: 5}, wantURL: regionalHost},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := mustNew(t, tc.cfg)
			ep, err := p.Resolve(context.Background(), tc.sel)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got endpoint %+v", ep)
				}
				if ep != (interfaces.BackendEndpoint{}) {
					t.Fatalf("error path must return a zero endpoint, got %+v", ep)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if ep.URL != tc.wantURL {
				t.Fatalf("URL = %q, want %q", ep.URL, tc.wantURL)
			}
			// The only mode Vertex serves is org-API; assert the resolved class explicitly
			// (not just == sel.Mode) so the contract is pinned independent of the selection.
			if ep.Mode != interfaces.ModeOrgAPI {
				t.Fatalf("Mode = %v, want ModeOrgAPI (the only class Vertex resolves)", ep.Mode)
			}
		})
	}
}

// TestResolve_ContextCancelled asserts a cancelled context is honoured before any routing.
func TestResolve_ContextCancelled(t *testing.T) {
	p := mustNew(t, Config{ProjectID: "p", Region: "us-east5"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Resolve(ctx, interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI}); err == nil {
		t.Fatal("expected a cancelled-context error")
	}
}

// TestConfig_RequiredFields asserts the fail-closed construction posture: no project, and no
// region for a regional backend, are rejected at New.
func TestConfig_RequiredFields(t *testing.T) {
	if _, err := New(Config{Region: "us-east5"}); err == nil {
		t.Fatal("expected New to reject a missing ProjectID")
	}
	if _, err := New(Config{ProjectID: "p"}); err == nil {
		t.Fatal("expected New to reject a missing Region when not Global")
	}
	// Global needs no region.
	if _, err := New(Config{ProjectID: "p", Global: true}); err != nil {
		t.Fatalf("global config should not require a region: %v", err)
	}
}

// TestConfig_RegionHostInjection asserts Region is validated against the GCP location grammar
// so it cannot forge a different host when interpolated into the regional endpoint.
func TestConfig_RegionHostInjection(t *testing.T) {
	bad := []string{
		"evil.com",          // would yield https://evil.com-aiplatform.googleapis.com
		"us-east5/../evil",  // path traversal in the authority
		"us-east5.evil.com", // dotted — escapes the intended host label
		"US-EAST5",          // uppercase (not GCP grammar)
		"us_east5",          // underscore
		"us-east",           // no trailing digit
		"https://evil.com",  // an embedded scheme
		"us",                // multi-region token — distinct host shape, use EndpointBaseURL
		"eu",                // multi-region token — distinct host shape, use EndpointBaseURL
		"",                  // empty (caught as missing region)
	}
	for _, in := range bad {
		t.Run("reject "+in, func(t *testing.T) {
			if _, err := New(Config{ProjectID: "p", Region: in}); err == nil {
				t.Fatalf("expected New to reject Region %q", in)
			}
		})
	}
	// Real GCP locations across the multi-token-geo forms MUST be accepted and resolve to
	// their regional host — this pins the single-hyphen grammar against an over-tightening
	// regression (the host-injection guard must not reject legitimate regions).
	good := []string{
		"us-east5", "us-central1", "us-west4", "europe-west1", "europe-west10",
		"me-central2", "asia-southeast1", "australia-southeast1", "northamerica-northeast1",
	}
	for _, in := range good {
		t.Run("accept "+in, func(t *testing.T) {
			p := mustNew(t, Config{ProjectID: "p", Region: in})
			ep, err := p.Resolve(context.Background(), interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if want := "https://" + in + "-aiplatform.googleapis.com"; ep.URL != want {
				t.Fatalf("URL = %q, want %q", ep.URL, want)
			}
		})
	}
}

// TestConfig_EndpointOverride covers the PSC/VPC-SC override validation: https-only,
// absolute-with-host, fail-closed on anything else, and no credential leak in errors.
func TestConfig_EndpointOverride(t *testing.T) {
	bad := []string{
		"http://vertex.vpc.example.com",    // cleartext
		"vertex.vpc.example.com",           // scheme-less / relative
		"https://",                         // no host
		"https://:443",                     // hostless authority, port only (u.Host != "" but u.Hostname() == "")
		"://nope",                          // malformed
		"https://user:pass@vertex.vpc.com", // userinfo (credential in config)
		"https://vertex.vpc.com?token=x",   // query on a base URL
		"https://vertex.vpc.com#frag",      // fragment on a base URL
	}
	for _, in := range bad {
		t.Run("reject "+in, func(t *testing.T) {
			if _, err := New(Config{ProjectID: "p", Region: "us-east5", EndpointBaseURL: in}); err == nil {
				t.Fatalf("expected New to reject EndpointBaseURL %q", in)
			}
		})
	}

	// A rejected override's error MUST NOT leak an embedded credential into a message a caller logs.
	for _, in := range []string{"http://user:s3cr3t@vertex.vpc.com", "https://user:s3cr3t@vertex.vpc.com?x=1"} {
		t.Run("no credential leak: "+in, func(t *testing.T) {
			_, err := New(Config{ProjectID: "p", Region: "us-east5", EndpointBaseURL: in})
			if err == nil {
				t.Fatalf("expected New to reject %q", in)
			}
			if strings.Contains(err.Error(), "s3cr3t") {
				t.Fatalf("error leaked the embedded credential: %v", err)
			}
		})
	}

	// A valid https override is accepted and used for the org-API route, taking precedence
	// over the region (which would otherwise yield the public regional host).
	const psc = "https://us-east5-aiplatform.vpc.example.com"
	p := mustNew(t, Config{ProjectID: "p", Region: "us-east5", EndpointBaseURL: psc})
	ep, err := p.Resolve(context.Background(), interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ep.URL != psc {
		t.Fatalf("org-api URL = %q, want the configured PSC override", ep.URL)
	}
}
