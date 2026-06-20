package inferenceanthropic

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

// TestResolve_Seam exercises the attended/unattended routing decision and the first-party
// pin against the SECURITY contract in sdk/interfaces/inference.go.
func TestResolve_Seam(t *testing.T) {
	const gateway = "https://anthropic-proxy.corp.example.com"
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
		{name: "unspecified mode fails closed", sel: interfaces.InferenceSelection{Attended: true, Beneficiaries: 1}, wantErr: true},
		{name: "unrecognised mode fails closed", sel: interfaces.InferenceSelection{Mode: interfaces.InferenceMode(99), Attended: true, Beneficiaries: 1}, wantErr: true},

		// Subscription happy path → first-party, regardless of the org gateway override.
		{name: "subscription enabled → first-party", cfg: Config{SubscriptionEnabled: true}, sel: sub(true, 1), wantURL: FirstPartyBaseURL},
		{name: "subscription pinned despite org gateway", cfg: Config{SubscriptionEnabled: true, OrgAPIBaseURL: gateway}, sel: sub(true, 1), wantURL: FirstPartyBaseURL},

		// Subscription refusals — each a distinct error, never a downgrade.
		{name: "subscription refused — unattended", cfg: Config{SubscriptionEnabled: true}, sel: sub(false, 1), wantErr: true},
		{name: "subscription refused — multi-beneficiary fan-out", cfg: Config{SubscriptionEnabled: true}, sel: sub(true, 2), wantErr: true},
		{name: "subscription refused — zero beneficiaries", cfg: Config{SubscriptionEnabled: true}, sel: sub(true, 0), wantErr: true},
		{name: "subscription refused — disabled by policy", cfg: Config{SubscriptionEnabled: false}, sel: sub(true, 1), wantErr: true},

		// Org-API route.
		{name: "org-api no override → first-party", sel: interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI}, wantURL: FirstPartyBaseURL},
		{name: "org-api with gateway override", cfg: Config{OrgAPIBaseURL: gateway}, sel: interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI}, wantURL: gateway},
		// An unattended / fan-out session on the org-API route is fine (that is the point).
		{name: "org-api unattended fan-out ok", cfg: Config{OrgAPIBaseURL: gateway}, sel: interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI, Attended: false, Beneficiaries: 5}, wantURL: gateway},
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
			if ep.Mode != tc.sel.Mode {
				t.Fatalf("Mode = %v, want %v (Resolve must echo the resolved class)", ep.Mode, tc.sel.Mode)
			}
		})
	}
}

// TestResolve_ContextCancelled asserts a cancelled context is honoured before any routing.
func TestResolve_ContextCancelled(t *testing.T) {
	p := mustNew(t, Config{SubscriptionEnabled: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Resolve(ctx, interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI}); err == nil {
		t.Fatal("expected a cancelled-context error")
	}
}

// TestConfigNormalize_OrgGateway covers the org-API gateway validation: https-only,
// absolute-with-host, fail-closed on anything else.
func TestConfigNormalize_OrgGateway(t *testing.T) {
	bad := []string{
		"http://anthropic-proxy.corp.example.com", // cleartext
		"anthropic-proxy.corp.example.com",        // scheme-less / relative
		"https://",                                // no host
		"https://:443",                            // hostless authority, port only (u.Host != "" but u.Hostname() == "")
		"://nope",                                 // malformed
		"https://user:pass@gw.example.com",        // userinfo (credential in config)
		"https://gw.example.com?token=x",          // query on a base URL
		"https://gw.example.com#frag",             // fragment on a base URL
	}
	for _, in := range bad {
		t.Run("reject "+in, func(t *testing.T) {
			if _, err := New(Config{OrgAPIBaseURL: in}); err == nil {
				t.Fatalf("expected New to reject OrgAPIBaseURL %q", in)
			}
		})
	}

	// A rejected URL's error MUST NOT leak an embedded credential into a message a caller logs.
	for _, in := range []string{"http://user:s3cr3t@gw.example.com", "https://user:s3cr3t@gw.example.com?x=1"} {
		t.Run("no credential leak: "+in, func(t *testing.T) {
			_, err := New(Config{OrgAPIBaseURL: in})
			if err == nil {
				t.Fatalf("expected New to reject %q", in)
			}
			if strings.Contains(err.Error(), "s3cr3t") {
				t.Fatalf("error leaked the embedded credential: %v", err)
			}
		})
	}

	// A valid https gateway is accepted and used for the org-API route.
	p, err := New(Config{OrgAPIBaseURL: "https://gw.corp.example.com/anthropic"})
	if err != nil {
		t.Fatalf("New with valid gateway: %v", err)
	}
	ep, err := p.Resolve(context.Background(), interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ep.URL != "https://gw.corp.example.com/anthropic" {
		t.Fatalf("org-api URL = %q, want the configured gateway", ep.URL)
	}
}

// TestZeroConfig_FailClosedSubscription asserts the zero-value Config refuses subscription
// (opt-in posture) but still serves the org-API route at first-party.
func TestZeroConfig_FailClosedSubscription(t *testing.T) {
	p := mustNew(t, Config{})
	if _, err := p.Resolve(context.Background(), interfaces.InferenceSelection{Mode: interfaces.ModeSubscription, Attended: true, Beneficiaries: 1}); err == nil {
		t.Fatal("zero-config must refuse subscription (disabled by default)")
	}
	ep, err := p.Resolve(context.Background(), interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI})
	if err != nil {
		t.Fatalf("org-api on zero config: %v", err)
	}
	if ep.URL != FirstPartyBaseURL {
		t.Fatalf("org-api URL = %q, want %q", ep.URL, FirstPartyBaseURL)
	}
}
