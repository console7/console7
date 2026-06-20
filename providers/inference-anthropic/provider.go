package inferenceanthropic

import (
	"context"
	"errors"

	"github.com/console7/console7/sdk/interfaces"
)

// Provider is the Anthropic reference InferenceBackend. It is immutable after New and holds
// no credential and no client — only the resolved routing policy.
type Provider struct {
	// subscriptionEnabled is the enterprise policy flip (Config.SubscriptionEnabled).
	subscriptionEnabled bool
	// orgAPIURL is the resolved ModeOrgAPI endpoint (FirstPartyBaseURL or an adopter gateway).
	// It is NEVER used for the subscription route — that is pinned to FirstPartyBaseURL.
	orgAPIURL string
}

// Compile-time assertion that Provider satisfies the seam.
var _ interfaces.InferenceBackend = (*Provider)(nil)

// Resolve selects the Anthropic endpoint for a session, enforcing the attended/unattended
// seam in policy (DESIGN.md §3; GOAL.md tenet 7). It fails closed: ModeUnspecified and any
// unrecognised mode are refused rather than defaulting to a credential class, and a
// ModeSubscription selection that is not attended, serves more than one beneficiary, or is
// disabled by enterprise policy is an ERROR — never a silent downgrade to org-API.
//
// SECURITY: the (Attended, Beneficiaries) facts are the discriminator, NOT the invocation
// mode — a forked/headless `claude -p` inside an attended single-user session carries
// Attended=true, Beneficiaries=1 and stays on ModeSubscription. ModeSubscription ALWAYS
// resolves to FirstPartyBaseURL; the org-API gateway override can never move it. The
// resolved URL is an in-band routing decision only — it MUST already be on the session's
// egress allowlist, which the boundary authoritatively enforces (GOAL.md tenet 2).
func (p *Provider) Resolve(ctx context.Context, sel interfaces.InferenceSelection) (interfaces.BackendEndpoint, error) {
	if err := ctx.Err(); err != nil {
		return interfaces.BackendEndpoint{}, err
	}
	switch sel.Mode {
	case interfaces.ModeSubscription:
		// Gate the enterprise policy flip FIRST — the cheapest, most authoritative check.
		// When subscription routing is disabled, refuse regardless of the session facts.
		if !p.subscriptionEnabled {
			return interfaces.BackendEndpoint{}, errors.New("inferenceanthropic: subscription refused — disabled by enterprise policy")
		}
		if !sel.Attended {
			return interfaces.BackendEndpoint{}, errors.New("inferenceanthropic: subscription refused — session is not attended")
		}
		if sel.Beneficiaries != 1 {
			return interfaces.BackendEndpoint{}, errors.New("inferenceanthropic: subscription refused — session serves more than one beneficiary")
		}
		// Pinned to first-party Anthropic, structurally — a seat token can never be fronted by
		// a gateway (DESIGN.md §3; GOAL.md tenet 7).
		return interfaces.BackendEndpoint{Mode: interfaces.ModeSubscription, URL: FirstPartyBaseURL}, nil
	case interfaces.ModeOrgAPI:
		return interfaces.BackendEndpoint{Mode: interfaces.ModeOrgAPI, URL: p.orgAPIURL}, nil
	default:
		// ModeUnspecified or any unrecognised value: fail closed.
		return interfaces.BackendEndpoint{}, errors.New("inferenceanthropic: inference mode unspecified or unrecognised — refusing to default")
	}
}
