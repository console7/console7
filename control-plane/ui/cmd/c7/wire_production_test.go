//go:build c7_live

package main

import (
	"context"
	"testing"

	inferencevertex "github.com/console7/console7/providers/inference-vertex"
	"github.com/console7/console7/sdk/interfaces"
)

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
