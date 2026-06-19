package broker

import (
	"context"
	"errors"

	"github.com/console7/console7/sdk/interfaces"
)

// This file is the broker's per-user subscription-vault surface. Each method is a thin
// pass-through to the SecretsProvider/InferenceBackend seam: the load-bearing invariants
// — sealing under a per-user key, refusing injection unless attended and single-
// beneficiary, fail-closed inference routing — live IN the seam (sdk/interfaces), not
// duplicated here where a second copy could drift from the first. The broker's value is
// carrying the right facts to the seam, not re-deciding them.

// StoreSubscription hands a user's freshly-captured subscription token to the
// SecretsProvider to be sealed under that user's key. The plaintext passes through the
// broker transiently and is never persisted or returned by it.
func (b *Broker) StoreSubscription(ctx context.Context, subject interfaces.Subject, token []byte) error {
	if b.Secrets == nil {
		return errors.New("broker: missing secrets seam")
	}
	return b.Secrets.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{
		Subject: subject,
		Token:   token,
	})
}

// InjectSubscription asks the SecretsProvider to inject a user's token into their own
// attended sandbox. The seam enforces attended && single-beneficiary && owning-sandbox;
// the broker only forwards the facts.
func (b *Broker) InjectSubscription(ctx context.Context, in interfaces.SubscriptionInjection) error {
	if b.Secrets == nil {
		return errors.New("broker: missing secrets seam")
	}
	return b.Secrets.InjectSubscriptionToken(ctx, in)
}

// ResolveInference asks the InferenceBackend to route a session to its model endpoint,
// enforcing the attended/unattended seam. The discriminator is the (Attended,
// Beneficiaries) facts in sel, not how the session was invoked. A nil seam is reported as
// an error, never a panic, so a caller (e.g. the orchestrator) can fail closed and tear
// down rather than crashing mid-session.
func (b *Broker) ResolveInference(ctx context.Context, sel interfaces.InferenceSelection) (interfaces.BackendEndpoint, error) {
	if b.Inference == nil {
		return interfaces.BackendEndpoint{}, errors.New("broker: missing inference seam")
	}
	return b.Inference.Resolve(ctx, sel)
}

// OpenPullRequest proposes the session's change as a pull request via the SCM seam (the
// only sanctioned exit). A nil seam is reported as an error, never a panic, so the caller
// can fail closed and tear down.
func (b *Broker) OpenPullRequest(ctx context.Context, pr interfaces.PullRequest) (interfaces.PRRef, error) {
	if b.SCM == nil {
		return interfaces.PRRef{}, errors.New("broker: missing scm seam")
	}
	return b.SCM.OpenPullRequest(ctx, pr)
}
