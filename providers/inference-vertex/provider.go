package inferencevertex

import (
	"context"
	"errors"

	"github.com/console7/console7/sdk/interfaces"
)

// Provider is the Vertex reference InferenceBackend. It is immutable after New and holds no
// credential and no client — only the resolved org-API endpoint. Vertex serves the org-API
// route exclusively; the subscription route is refused (see doc.go).
type Provider struct {
	// endpointURL is the resolved ModeOrgAPI Vertex endpoint (regional host, GlobalHost, or
	// a validated PSC/VPC-SC override). It is the only state the router carries.
	endpointURL string
}

// Compile-time assertion that Provider satisfies the seam.
var _ interfaces.InferenceBackend = (*Provider)(nil)

// Resolve selects the Vertex endpoint for a session, enforcing the attended/unattended seam
// in policy (DESIGN.md §3; GOAL.md tenet 2). It fails closed: ModeUnspecified and any
// unrecognised mode are refused rather than defaulting to a credential class.
//
// SECURITY: Vertex refuses EVERY ModeSubscription selection — a personal Anthropic seat token
// has no meaning against Vertex (disjoint auth and billing), so there is no route to fabricate.
// This is stricter than the contract floor (which refuses only unattended/multi-beneficiary
// subscription) and is deliberate; an attended subscription session belongs on the
// direct-Anthropic backend. ModeOrgAPI — every unattended or multi-beneficiary session —
// resolves to the configured in-tenancy Vertex endpoint. The resolved URL is an in-band
// routing decision only: it MUST already be on the session's egress allowlist, which the
// boundary authoritatively enforces (GOAL.md tenet 3).
func (p *Provider) Resolve(ctx context.Context, sel interfaces.InferenceSelection) (interfaces.BackendEndpoint, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.BackendEndpoint{}, err
	}
	switch sel.Mode {
	case interfaces.ModeSubscription:
		// Vertex cannot back a subscription seat — refuse outright, never downgrade to org-API.
		return interfaces.BackendEndpoint{}, errors.New("inferencevertex: subscription refused — Vertex is an org-API in-tenancy backend; a subscription credential does not route through Vertex (use the direct-Anthropic backend for attended subscription sessions)")
	case interfaces.ModeOrgAPI:
		return interfaces.BackendEndpoint{Mode: interfaces.ModeOrgAPI, URL: p.endpointURL}, nil
	default:
		// ModeUnspecified or any unrecognised value: fail closed.
		return interfaces.BackendEndpoint{}, errors.New("inferencevertex: inference mode unspecified or unrecognised — refusing to default")
	}
}
