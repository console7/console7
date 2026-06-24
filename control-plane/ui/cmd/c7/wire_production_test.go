//go:build c7_live

package main

import (
	"context"
	"errors"
	"os"
	"testing"

	inferencevertex "github.com/console7/console7/providers/inference-vertex"
	"github.com/console7/console7/sdk/interfaces"
	"golang.org/x/oauth2"
)

// TestImpersonationOpts pins the per-seam SA-impersonation wiring: an empty knob yields NO extra
// client option AND no error (the seam keeps ambient-ADC behaviour, unchanged); a non-empty knob
// yields exactly one option; and a token-source construction error propagates (fail closed — never
// silently fall back to ambient ADC). This is the mechanism that un-fuses the GCP seams' identities
// and restores the keybroker CA's DISTINCT signing identity (GOAL.md tenet 2). The real token source
// needs ADC, so we substitute the package-level factory with a static source — option.ClientOption
// is opaque (unexported methods), so we assert on the slice length, the only stable contract.
func TestImpersonationOpts(t *testing.T) {
	ctx := context.Background()

	if got, err := impersonationOpts(ctx, ""); err != nil || got != nil {
		t.Errorf("empty SA email: opts=%v err=%v, want nil,nil (no impersonation ⇒ ambient ADC)", got, err)
	}

	orig := impersonatedTokenSource
	t.Cleanup(func() { impersonatedTokenSource = orig })

	impersonatedTokenSource = func(context.Context, string) (oauth2.TokenSource, error) {
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake"}), nil
	}
	got, err := impersonationOpts(ctx, "keybroker@acme-prod.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("set SA email: unexpected err %v", err)
	}
	if len(got) != 1 {
		t.Errorf("set SA email: len(opts) = %d, want 1 (one WithTokenSource option)", len(got))
	}

	impersonatedTokenSource = func(context.Context, string) (oauth2.TokenSource, error) {
		return nil, errors.New("boom")
	}
	if _, err := impersonationOpts(ctx, "x@acme-prod.iam.gserviceaccount.com"); err == nil {
		t.Error("token-source error: want propagated error, got nil")
	}
}

// TestLoadProdEnv_ImpersonationKnobs pins that the optional per-seam knobs flow from the environment
// into prodEnv: each defaults to empty (⇒ ambient ADC, no behaviour change) and is read verbatim when
// set. It exercises loadProdEnv end-to-end with the rest of the required env satisfied so the knob
// plumbing is covered, not just the helper. Tagged c7_live because loadProdEnv lives in the
// production wiring; it touches no real tenancy (reads env + a dummy key file only).
func TestLoadProdEnv_ImpersonationKnobs(t *testing.T) {
	// Minimal required env so loadProdEnv reaches the optional-knob block. The GitHub App key is a
	// throwaway path written below — never a real credential.
	keyFile := t.TempDir() + "/app.pem"
	if err := os.WriteFile(keyFile, []byte("-- not a real key --"), 0o600); err != nil {
		t.Fatalf("write dummy key: %v", err)
	}
	setRequired := func(t *testing.T) {
		t.Helper()
		t.Setenv("C7_GKE_PROJECT", "acme-prod")
		t.Setenv("C7_GKE_LOCATION", "us-east5")
		t.Setenv("C7_GKE_CLUSTER", "c7")
		t.Setenv("C7_SANDBOX_IMAGE", "img@sha256:abc")
		t.Setenv("C7_KEK_RESOURCE", "kek")
		t.Setenv("C7_REGION", "us-east5")
		t.Setenv("C7_WORKLOAD_SA_EMAIL", "workload@acme-prod.iam.gserviceaccount.com")
		t.Setenv("C7_KMS_KEY_VERSION", "kmsver")
		t.Setenv("C7_EVIDENCE_BUCKET", "bucket")
		t.Setenv("C7_INFERENCE", "vertex")
		t.Setenv("C7_GH_APP_ID", "1")
		t.Setenv("C7_GH_INSTALLATION_ID", "2")
		t.Setenv("C7_GH_APP_KEY_FILE", keyFile)
	}

	t.Run("knobs default to empty (ambient ADC)", func(t *testing.T) {
		setRequired(t)
		t.Setenv("C7_KEYBROKER_SA_EMAIL", "")
		t.Setenv("C7_SECRETS_SA_EMAIL", "")
		t.Setenv("C7_EVIDENCE_SA_EMAIL", "")
		p, err := loadProdEnv()
		if err != nil {
			t.Fatalf("loadProdEnv: %v", err)
		}
		if p.keybrokerSA != "" || p.secretsSA != "" || p.evidenceSA != "" {
			t.Errorf("unset knobs: keybrokerSA=%q secretsSA=%q evidenceSA=%q, want all empty",
				p.keybrokerSA, p.secretsSA, p.evidenceSA)
		}
		// The empty-knob ⇒ no-option contract is covered by TestImpersonationOpts; here we only pin
		// that loadProdEnv plumbs the knobs.
	})

	t.Run("knobs read verbatim when set", func(t *testing.T) {
		setRequired(t)
		t.Setenv("C7_KEYBROKER_SA_EMAIL", "keybroker@acme-prod.iam.gserviceaccount.com")
		t.Setenv("C7_SECRETS_SA_EMAIL", "secrets@acme-prod.iam.gserviceaccount.com")
		t.Setenv("C7_EVIDENCE_SA_EMAIL", "evidence@acme-prod.iam.gserviceaccount.com")
		p, err := loadProdEnv()
		if err != nil {
			t.Fatalf("loadProdEnv: %v", err)
		}
		if p.keybrokerSA != "keybroker@acme-prod.iam.gserviceaccount.com" {
			t.Errorf("keybrokerSA = %q, want the set value", p.keybrokerSA)
		}
		if p.secretsSA != "secrets@acme-prod.iam.gserviceaccount.com" {
			t.Errorf("secretsSA = %q, want the set value", p.secretsSA)
		}
		if p.evidenceSA != "evidence@acme-prod.iam.gserviceaccount.com" {
			t.Errorf("evidenceSA = %q, want the set value", p.evidenceSA)
		}
		// The set-knob ⇒ one-option contract is covered by TestImpersonationOpts (with a substituted
		// token source, since the real one needs ADC); here we only pin the env plumbing.
	})
}

// TestBuildInference_VertexGlobalVsRegional pins finding #1: a resolved Vertex region of "global" is
// the engine's location-independent endpoint, NOT a GCP regional location, so buildInference must
// select it via Config.Global (→ GlobalHost) rather than threading "global" through Config.Region
// (which fails inference-vertex's regional-host grammar guard and would abort prod wiring). Any other
// value stays the regional lane. It is tagged c7_live because buildInference lives in the
// production wiring; it touches no real tenancy (inferencevertex.Resolve is pure).
func TestBuildInference_VertexGlobalVsRegional(t *testing.T) {
	resolve := func(t *testing.T, p *prodEnv) interfaces.BackendEndpoint {
		t.Helper()
		inf, _, err := buildInference(p)
		if err != nil {
			t.Fatalf("buildInference: %v", err)
		}
		ep, err := inf.Resolve(context.Background(), interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI, Beneficiaries: 1})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		return ep
	}

	t.Run("global region selects the location-independent endpoint", func(t *testing.T) {
		// C7_VERTEX_REGION / C7_VERTEX_PROJECT unset, so envOr falls back to p.region/p.project.
		t.Setenv("C7_VERTEX_REGION", "")
		t.Setenv("C7_VERTEX_PROJECT", "")
		t.Setenv("C7_VERTEX_MODEL", "")
		ep := resolve(t, &prodEnv{inferenceKind: "vertex", project: "acme-prod-123", region: "global"})
		if ep.URL != inferencevertex.GlobalHost {
			t.Errorf("global region: URL = %q, want GlobalHost %q", ep.URL, inferencevertex.GlobalHost)
		}
		if ep.VertexRegion != "global" {
			t.Errorf("global region: VertexRegion = %q, want %q", ep.VertexRegion, "global")
		}
	})

	t.Run("a real region stays the regional host", func(t *testing.T) {
		t.Setenv("C7_VERTEX_REGION", "")
		t.Setenv("C7_VERTEX_PROJECT", "")
		t.Setenv("C7_VERTEX_MODEL", "")
		ep := resolve(t, &prodEnv{inferenceKind: "vertex", project: "acme-prod-123", region: "us-east5"})
		if want := "https://us-east5-aiplatform.googleapis.com"; ep.URL != want {
			t.Errorf("regional: URL = %q, want %q", ep.URL, want)
		}
		if ep.VertexRegion != "us-east5" {
			t.Errorf("regional: VertexRegion = %q, want %q", ep.VertexRegion, "us-east5")
		}
	})

	t.Run("C7_VERTEX_REGION=global overrides a regional p.region", func(t *testing.T) {
		// The explicit env knob takes precedence over the shared C7_REGION fallback, and must also
		// route through Config.Global rather than the regional grammar.
		t.Setenv("C7_VERTEX_REGION", "global")
		t.Setenv("C7_VERTEX_PROJECT", "")
		t.Setenv("C7_VERTEX_MODEL", "")
		ep := resolve(t, &prodEnv{inferenceKind: "vertex", project: "acme-prod-123", region: "us-east5"})
		if ep.URL != inferencevertex.GlobalHost {
			t.Errorf("C7_VERTEX_REGION=global: URL = %q, want GlobalHost %q", ep.URL, inferencevertex.GlobalHost)
		}
	})
}
