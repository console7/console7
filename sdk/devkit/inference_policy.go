package devkit

import (
	"context"
	"errors"

	"github.com/console7/console7/sdk/interfaces"
)

// SeamPolicy is the configurable enterprise policy behind the attended/unattended seam.
// It exists so the routing trigger is policy, not architecture (DESIGN.md §3): an
// enterprise can disable subscription routing entirely (SubscriptionEnabled=false) or
// move endpoints without changing code.
type SeamPolicy struct {
	// SubscriptionEndpoint is the resolved inference endpoint for an attended,
	// single-beneficiary session. PRECONDITION (not enforced here — there is no egress
	// allowlist until Phase 1): the adopter must ensure it is on the session's egress
	// allowlist, since the boundary is the authoritative control (inference.go).
	SubscriptionEndpoint string
	// OrgAPIEndpoint backs every unattended or multi-beneficiary session.
	OrgAPIEndpoint string
	// SubscriptionEnabled lets an enterprise turn off subscription routing as a policy
	// flip. When false, even a valid attended single-beneficiary selection is refused.
	SubscriptionEnabled bool
}

// PolicyInference is an in-memory, NON-PRODUCTION InferenceBackend that enforces the
// attended/unattended seam. It models the routing contract, not a real Vertex/Anthropic
// endpoint resolution.
type PolicyInference struct {
	policy SeamPolicy
}

var _ interfaces.InferenceBackend = (*PolicyInference)(nil)

// NewPolicyInference returns a PolicyInference governed by p.
func NewPolicyInference(p SeamPolicy) *PolicyInference {
	return &PolicyInference{policy: p}
}

// Resolve selects the backend endpoint, enforcing the seam:
//   - ModeUnspecified (and any unrecognised mode) is rejected — fail closed, never a
//     silent default to a credential class.
//   - ModeSubscription is honoured ONLY when the session is attended AND serves exactly
//     one beneficiary AND the enterprise enables subscription routing. A selection that
//     asks for subscription without meeting these is an ERROR, not a silent downgrade,
//     so a forced subscription on a fan-out is caught rather than quietly served.
//   - ModeOrgAPI backs everything without a present human or with more than one
//     beneficiary.
//
// The discriminator is the (Attended, Beneficiaries) facts, NOT the invocation mode: a
// forked/headless `claude -p` inside an attended single-user session carries
// Attended=true, Beneficiaries=1 — the SAME selection as the interactive case — so it
// stays on ModeSubscription and is not rerouted.
func (i *PolicyInference) Resolve(ctx context.Context, sel interfaces.InferenceSelection) (interfaces.BackendEndpoint, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.BackendEndpoint{}, err
	}
	switch sel.Mode {
	case interfaces.ModeSubscription:
		if !sel.Attended {
			return interfaces.BackendEndpoint{}, errors.New("devkit: subscription refused — session is not attended")
		}
		if sel.Beneficiaries != 1 {
			return interfaces.BackendEndpoint{}, errors.New("devkit: subscription refused — session serves more than one beneficiary")
		}
		if !i.policy.SubscriptionEnabled {
			return interfaces.BackendEndpoint{}, errors.New("devkit: subscription refused — disabled by enterprise policy")
		}
		if i.policy.SubscriptionEndpoint == "" {
			return interfaces.BackendEndpoint{}, errors.New("devkit: subscription endpoint not configured")
		}
		return interfaces.BackendEndpoint{Mode: interfaces.ModeSubscription, URL: i.policy.SubscriptionEndpoint, Kind: interfaces.BackendAnthropicAPI}, nil
	case interfaces.ModeOrgAPI:
		if i.policy.OrgAPIEndpoint == "" {
			return interfaces.BackendEndpoint{}, errors.New("devkit: org-API endpoint not configured")
		}
		return interfaces.BackendEndpoint{Mode: interfaces.ModeOrgAPI, URL: i.policy.OrgAPIEndpoint, Kind: interfaces.BackendAnthropicAPI}, nil
	default:
		// ModeUnspecified or any unrecognised value: fail closed.
		return interfaces.BackendEndpoint{}, errors.New("devkit: inference mode unspecified or unrecognised — refusing to default")
	}
}
