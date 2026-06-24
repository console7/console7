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

// InjectOrgCredential asks the SecretsProvider to inject the adopter's shared ORG API
// credential into a session's sandbox (the org-API lane — orchestrated/headless work, or an
// attended session that did not opt into its subscription; GOAL.md tenet 2). The seam verifies
// the sandbox belongs to the session and injects only there; the broker only forwards the facts
// and never carries the plaintext.
func (b *Broker) InjectOrgCredential(ctx context.Context, in interfaces.OrgCredentialInjection) error {
	if b.Secrets == nil {
		return errors.New("broker: missing secrets seam")
	}
	return b.Secrets.InjectOrgCredential(ctx, in)
}

// InjectInferenceCredential asks the SecretsProvider to MINT a short-lived cloud inference
// credential (a GCP bearer for the in-tenancy Vertex lane) and inject it into the session's own
// sandbox. The seam mints + delivers inside the provider (the broker and control plane never see the
// token), verifies the owning sandbox, and caps the token to the session deadline; the broker only
// forwards the facts.
func (b *Broker) InjectInferenceCredential(ctx context.Context, in interfaces.InferenceCredentialInjection) error {
	if b.Secrets == nil {
		return errors.New("broker: missing secrets seam")
	}
	return b.Secrets.InjectInferenceCredential(ctx, in)
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

// FetchRepoBundle fetches the base branch as a git bundle via the SCM seam, for the control plane
// to seed into the sandbox (the push→PR bridge; the sandbox never fetches from the SCM itself).
func (b *Broker) FetchRepoBundle(ctx context.Context, repo interfaces.RepoRef, baseBranch string) ([]byte, error) {
	if b.SCM == nil {
		return nil, errors.New("broker: missing scm seam")
	}
	return b.SCM.FetchRepoBundle(ctx, repo, baseBranch)
}

// PushBranch pushes the session's working branch (carried as a git bundle) via the SCM seam — the
// control-plane half of the push→PR bridge. The push credential stays in the SCM provider; the
// broker only forwards the request (it holds no SCM token itself).
func (b *Broker) PushBranch(ctx context.Context, req interfaces.PushBranchRequest) error {
	if b.SCM == nil {
		return errors.New("broker: missing scm seam")
	}
	return b.SCM.PushBranch(ctx, req)
}
