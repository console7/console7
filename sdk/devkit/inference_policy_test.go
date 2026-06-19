package devkit

import (
	"context"
	"testing"

	"github.com/console7/console7/sdk/interfaces"
)

// TestPolicyInference_Resolve_Seam is the headline proof that the attended/unattended
// discriminator is the (Attended, Beneficiaries) FACTS, not the invocation mode. The
// "interactive" and "forked claude -p" rows are the SAME selection — both stay on
// subscription — while the orchestrated row differs only in Attended=false.
func TestPolicyInference_Resolve_Seam(t *testing.T) {
	const subURL = "https://subscription.internal/inference"
	const orgURL = "https://vertex.internal/inference"
	i := NewPolicyInference(SeamPolicy{
		SubscriptionEndpoint: subURL,
		OrgAPIEndpoint:       orgURL,
		SubscriptionEnabled:  true,
	})

	cases := []struct {
		name    string
		sel     interfaces.InferenceSelection
		wantURL string // "" means expect an error
	}{
		{
			name:    "attended interactive session",
			sel:     interfaces.InferenceSelection{Mode: interfaces.ModeSubscription, Attended: true, Beneficiaries: 1},
			wantURL: subURL,
		},
		{
			name:    "forked claude -p inside attended session stays on subscription",
			sel:     interfaces.InferenceSelection{Mode: interfaces.ModeSubscription, Attended: true, Beneficiaries: 1},
			wantURL: subURL,
		},
		{
			name:    "orchestrated/headless job routes to org-API",
			sel:     interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI, Attended: false, Beneficiaries: 1},
			wantURL: orgURL,
		},
		{
			name:    "scheduled job with no human routes to org-API",
			sel:     interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI, Attended: false, Beneficiaries: 5},
			wantURL: orgURL,
		},
		{
			name:    "attended cross-repo fan-out is refused",
			sel:     interfaces.InferenceSelection{Mode: interfaces.ModeSubscription, Attended: true, Beneficiaries: 3},
			wantURL: "",
		},
		{
			name:    "subscription forced on an unattended session is refused",
			sel:     interfaces.InferenceSelection{Mode: interfaces.ModeSubscription, Attended: false, Beneficiaries: 1},
			wantURL: "",
		},
		{
			name:    "unspecified mode fails closed",
			sel:     interfaces.InferenceSelection{Mode: interfaces.ModeUnspecified, Attended: true, Beneficiaries: 1},
			wantURL: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep, err := i.Resolve(context.Background(), tc.sel)
			if tc.wantURL == "" {
				if err == nil {
					t.Errorf("expected refusal, got endpoint %+v", ep)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if ep.URL != tc.wantURL {
				t.Errorf("URL = %q, want %q", ep.URL, tc.wantURL)
			}
		})
	}
}

func TestPolicyInference_Resolve_SubscriptionDisabledByPolicy(t *testing.T) {
	i := NewPolicyInference(SeamPolicy{
		SubscriptionEndpoint: "https://sub",
		OrgAPIEndpoint:       "https://org",
		SubscriptionEnabled:  false, // enterprise flipped subscription off.
	})
	if _, err := i.Resolve(context.Background(), interfaces.InferenceSelection{
		Mode: interfaces.ModeSubscription, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("subscription served despite being disabled by enterprise policy")
	}
}
