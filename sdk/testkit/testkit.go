package testkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// ProviderUnderTest bundles the provider implementations a conformance run exercises.
// Every field is optional: a run asserts contracts only for the providers supplied,
// so an adopter shipping a single provider can conform just that one. The fields are
// the nine seams from ARCHITECTURE.md §5.
type ProviderUnderTest struct {
	Cloud     interfaces.CloudProvider
	Secrets   interfaces.SecretsProvider
	Identity  interfaces.IdentityProvider
	SCM       interfaces.SCMProvider
	Inference interfaces.InferenceBackend
	Policy    interfaces.PolicyEngine
	PolicySoR interfaces.PolicySoR
	Evidence  interfaces.EvidenceSink
	Observe   interfaces.ObserveGateway

	// SecretsRig is an OPTIONAL test capability. The SecretsProvider interface alone
	// cannot mint an owned SandboxHandle, so without a rig the InjectSubscriptionToken
	// check can only probe the refusal paths with a bogus handle — and a provider that
	// rejects unknown handles but SKIPS the attended/beneficiary checks would pass
	// spuriously. Supplying a rig lets the suite provision a real owned sandbox and
	// confirm the attended/single-beneficiary gate is what drives the refusals (the
	// attended single-beneficiary case must succeed).
	SecretsRig SubscriptionTestRig
}

// SubscriptionTestRig provisions a sandbox owned by a (subject, session) so the
// conformance suite can exercise subscription injection against a real, owned target.
type SubscriptionTestRig interface {
	Provision(subject interfaces.Subject, session interfaces.SessionID) interfaces.SandboxHandle
}

// Contract names one provider-interface method whose SECURITY clause a conformance
// check must uphold. It is the unit the harness is keyed to: one Contract per
// must-never guarantee in sdk/interfaces.
type Contract struct {
	// Interface is the provider interface, e.g. "SecretsProvider".
	Interface string
	// Method is the method under contract, e.g. "MintEphemeral".
	Method string
	// MustNever restates, in one line, the guarantee the check asserts — e.g.
	// "never returns long-lived credential material to the control plane".
	MustNever string
}

// ErrProviderAbsent is returned by RunContract when no implementation was supplied for
// the contract's interface, so a caller can skip rather than fail.
var ErrProviderAbsent = errors.New("testkit: provider not supplied for this contract")

// check pairs a Contract with the assertion that upholds it and a predicate that reports
// whether the relevant provider was supplied. The assertion uses ONLY interface methods,
// so it holds for any conforming implementation, not just the dev/in-memory ones.
//
// SCOPE: these assertions cover the contract guarantees that are observable THROUGH the
// interface — expiry caps, fail-closed routing, attended-only refusals, protected-branch
// refusals, unverifiable-token rejection. The guarantees that are deliberately NOT
// observable through the interface (a SecretsProvider has no plaintext read path, so
// "no operator read path", "per-user key", and "no pooling" cannot be probed from
// outside) are asserted by each implementation's own white-box tests instead — see
// sdk/devkit/*_test.go. A green run here is not, on its own, proof of the cryptographic-
// boundary invariants; that distinction is recorded in docs/THREAT-MODEL.md §1/§4.
type check struct {
	contract Contract
	present  func(ProviderUnderTest) bool
	run      func(ctx context.Context, put ProviderUnderTest) error
}

// registry is the set of contracts the suite can assert. Phase 0 covers the four seams
// that have an implementation (Secrets, Identity, SCM, Inference); the remaining seams'
// contracts are asserted as their providers land (docs/ROADMAP.md), and until then their
// conformance cases skip.
func registry() []check {
	const confSubject = interfaces.Subject("conf-subject")
	confRepo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}

	hasSecrets := func(p ProviderUnderTest) bool { return p.Secrets != nil }
	hasIdentity := func(p ProviderUnderTest) bool { return p.Identity != nil }
	hasSCM := func(p ProviderUnderTest) bool { return p.SCM != nil }
	hasInference := func(p ProviderUnderTest) bool { return p.Inference != nil }

	return []check{
		{
			contract: Contract{"SecretsProvider", "MintEphemeral", "return long-lived or plaintext credential material to the control plane, or grant wider scope/TTL than requested"},
			present:  hasSecrets,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				// NOTE: the "no wider scope than requested" half of this contract is not
				// observable through the interface — a CredentialRef is opaque and carries
				// no scope — so only the expiry guarantees are asserted here. Scope-capping
				// is the implementation's own (white-box) responsibility.
				now := time.Now()
				deadline := now.Add(2 * time.Minute)
				// A TTL longer than the deadline must be capped to the deadline.
				ref, err := p.Secrets.MintEphemeral(ctx, interfaces.EphemeralRequest{
					SessionID: "conf", Subject: confSubject, Scopes: []string{"repo:read"},
					TTL: time.Hour, SessionDeadline: deadline,
				})
				if err != nil {
					return fmt.Errorf("MintEphemeral with a valid request errored: %w", err)
				}
				if ref.Ref == "" {
					return errors.New("returned an empty CredentialRef.Ref")
				}
				if ref.Expiry.IsZero() {
					return errors.New("returned a zero Expiry (invalid per the CredentialRef contract)")
				}
				if !ref.Expiry.After(now) {
					return fmt.Errorf("credential expiry %v is not in the future (already-expired)", ref.Expiry)
				}
				if ref.Expiry.After(deadline) {
					return fmt.Errorf("credential expiry %v outlives the session deadline %v", ref.Expiry, deadline)
				}
				// A TTL shorter than the deadline must bound the expiry to ~now+TTL.
				ttl := time.Minute
				ref2, err := p.Secrets.MintEphemeral(ctx, interfaces.EphemeralRequest{
					SessionID: "conf", Subject: confSubject, TTL: ttl, SessionDeadline: now.Add(time.Hour),
				})
				if err != nil {
					return fmt.Errorf("MintEphemeral (short TTL) errored: %w", err)
				}
				if !ref2.Expiry.After(now) {
					return fmt.Errorf("short-TTL credential expiry %v is not in the future", ref2.Expiry)
				}
				if ref2.Expiry.After(now.Add(ttl + 5*time.Second)) {
					return fmt.Errorf("credential expiry %v exceeds now+TTL", ref2.Expiry)
				}
				return nil
			},
		},
		{
			contract: Contract{"SecretsProvider", "StoreSubscriptionToken", "store under a shared key, leave a standing operator read path, or pool the token"},
			present:  hasSecrets,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				// Interface-observable: a valid token is accepted, and the interface
				// exposes no plaintext read path by construction. The per-user-key /
				// no-pooling invariant is asserted white-box (see check doc).
				if err := p.Secrets.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{
					Subject: confSubject, Token: []byte("conf-subscription-token"),
				}); err != nil {
					return fmt.Errorf("StoreSubscriptionToken with a valid token errored: %w", err)
				}
				return nil
			},
		},
		{
			contract: Contract{"SecretsProvider", "InjectSubscriptionToken", "return plaintext to the caller, inject into a non-owner sandbox, or back an unattended session"},
			present:  hasSecrets,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				dummy := interfaces.SandboxHandle{ID: "conf-nonexistent-sandbox"}
				// Must refuse an unattended injection (the refusal must not depend on the
				// handle being valid — an attended check fails closed regardless).
				if err := p.Secrets.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
					Subject: confSubject, SessionID: "conf", Sandbox: dummy, Attended: false, Beneficiaries: 1,
				}); err == nil {
					return errors.New("injected a subscription token into an unattended session")
				}
				// Must refuse a multi-beneficiary injection.
				if err := p.Secrets.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
					Subject: confSubject, SessionID: "conf", Sandbox: dummy, Attended: true, Beneficiaries: 2,
				}); err == nil {
					return errors.New("injected a subscription token for a multi-beneficiary session")
				}
				// Without a rig the above only proves "some error" — a provider could pass
				// by rejecting the unknown handle while ignoring the attended/beneficiary
				// gate. With a rig, exercise the gate against a REAL owned sandbox so the
				// refusals are attributable to it, and confirm the valid case succeeds.
				if p.SecretsRig == nil {
					return nil
				}
				const owner = interfaces.Subject("conf-inject-owner")
				const session = interfaces.SessionID("conf-inject")
				if err := p.Secrets.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{
					Subject: owner, Token: []byte("conf-inject-token"),
				}); err != nil {
					return fmt.Errorf("StoreSubscriptionToken (for injection check) errored: %w", err)
				}
				owned := p.SecretsRig.Provision(owner, session)
				other := p.SecretsRig.Provision("conf-inject-other", "conf-inject-other-session")
				// Valid owned sandbox, but unattended / fan-out / non-owner must still refuse.
				if err := p.Secrets.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
					Subject: owner, SessionID: session, Sandbox: owned, Attended: false, Beneficiaries: 1,
				}); err == nil {
					return errors.New("injected into an unattended session despite a valid owned sandbox")
				}
				if err := p.Secrets.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
					Subject: owner, SessionID: session, Sandbox: owned, Attended: true, Beneficiaries: 2,
				}); err == nil {
					return errors.New("injected for a multi-beneficiary session despite a valid owned sandbox")
				}
				if err := p.Secrets.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
					Subject: owner, SessionID: session, Sandbox: other, Attended: true, Beneficiaries: 1,
				}); err == nil {
					return errors.New("injected into a non-owner sandbox")
				}
				// The attended, single-beneficiary case into the owner's sandbox must
				// succeed — proving the refusals above came from the gate, not the handle.
				if err := p.Secrets.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
					Subject: owner, SessionID: session, Sandbox: owned, Attended: true, Beneficiaries: 1,
				}); err != nil {
					return fmt.Errorf("attended single-beneficiary injection into the owner sandbox should succeed: %w", err)
				}
				return nil
			},
		},
		{
			contract: Contract{"SecretsProvider", "RevokeSubject", "retain a recoverable copy of revoked material"},
			present:  hasSecrets,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				// Interface-observable: revocation succeeds. Unrecoverability is not
				// probeable through the interface (no read path) and is asserted white-box.
				if err := p.Secrets.RevokeSubject(ctx, "conf-subject-to-revoke"); err != nil {
					return fmt.Errorf("RevokeSubject errored: %w", err)
				}
				return nil
			},
		},
		{
			contract: Contract{"IdentityProvider", "Authenticate", "trust client-asserted claims without cryptographic verification, or mint/persist a long-lived session secret"},
			present:  hasIdentity,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				if _, err := p.Identity.Authenticate(ctx, "garbage-unverifiable-assertion"); err == nil {
					return errors.New("authenticated an unverifiable assertion")
				}
				return nil
			},
		},
		{
			contract: Contract{"IdentityProvider", "ResolveGroups", "let a subject self-assert or widen its own group membership"},
			present:  hasIdentity,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				// An unknown subject must resolve without error and without fabricated
				// membership; the only input is the subject name, so it cannot self-assert.
				groups, err := p.Identity.ResolveGroups(ctx, "conf-unknown-subject")
				if err != nil {
					return fmt.Errorf("ResolveGroups errored for an unknown subject: %w", err)
				}
				if len(groups) != 0 {
					return fmt.Errorf("fabricated %d groups for an unknown subject", len(groups))
				}
				return nil
			},
		},
		{
			contract: Contract{"SCMProvider", "MintWorkingCredential", "issue a durable token, allow push beyond the working branch, or let the sandbox git client see long-lived material"},
			present:  hasSCM,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				now := time.Now()
				deadline := now.Add(30 * time.Minute)
				// Must refuse to scope a credential to a protected/default branch.
				if _, err := p.SCM.MintWorkingCredential(ctx, interfaces.WorkingCredentialRequest{
					Subject: confSubject, SessionID: "conf", Repo: confRepo, Branch: "main", SessionDeadline: deadline,
				}); err == nil {
					return errors.New("minted a working credential scoped to the protected branch main")
				}
				// Must issue a short-lived, opaque ref for a working branch.
				ref, err := p.SCM.MintWorkingCredential(ctx, interfaces.WorkingCredentialRequest{
					Subject: confSubject, SessionID: "conf", Repo: confRepo, Branch: "feature/conf", SessionDeadline: deadline,
				})
				if err != nil {
					return fmt.Errorf("MintWorkingCredential for a working branch errored: %w", err)
				}
				if ref.Ref == "" {
					return errors.New("returned an empty CredentialRef.Ref")
				}
				if ref.Expiry.IsZero() || !ref.Expiry.After(now) {
					return fmt.Errorf("credential is not short-lived with a future expiry: %v", ref.Expiry)
				}
				// Must not outlive the session deadline.
				if ref.Expiry.After(deadline) {
					return fmt.Errorf("credential expiry %v outlives the session deadline %v", ref.Expiry, deadline)
				}
				return nil
			},
		},
		{
			contract: Contract{"SCMProvider", "OpenPullRequest", "push to/merge a protected branch, or self-approve or actuate the change"},
			present:  hasSCM,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				// Must refuse head == base (a direct mutation, not a proposal).
				if _, err := p.SCM.OpenPullRequest(ctx, interfaces.PullRequest{
					Repo: confRepo, Head: "main", Base: "main",
				}); err == nil {
					return errors.New("opened a pull request whose head equals its base")
				}
				ref, err := p.SCM.OpenPullRequest(ctx, interfaces.PullRequest{
					Repo: confRepo, Head: "feature/conf", Base: "main", Title: "conf",
				})
				if err != nil {
					return fmt.Errorf("OpenPullRequest for a valid proposal errored: %w", err)
				}
				if ref.Number == 0 && ref.URL == "" {
					return errors.New("returned an empty PRRef")
				}
				return nil
			},
		},
		{
			contract: Contract{"InferenceBackend", "Resolve", "back an unattended or multi-beneficiary session with a subscription credential, or pool a subscription across beneficiaries"},
			present:  hasInference,
			run: func(ctx context.Context, p ProviderUnderTest) error {
				// Fail closed on the zero/unspecified mode.
				if _, err := p.Inference.Resolve(ctx, interfaces.InferenceSelection{
					Mode: interfaces.ModeUnspecified, Attended: true, Beneficiaries: 1,
				}); err == nil {
					return errors.New("resolved ModeUnspecified instead of failing closed")
				}
				// Subscription must be refused for an unattended session.
				if _, err := p.Inference.Resolve(ctx, interfaces.InferenceSelection{
					Mode: interfaces.ModeSubscription, Attended: false, Beneficiaries: 1,
				}); err == nil {
					return errors.New("backed an unattended session with a subscription credential")
				}
				// Subscription must be refused for a multi-beneficiary (fan-out) session.
				if _, err := p.Inference.Resolve(ctx, interfaces.InferenceSelection{
					Mode: interfaces.ModeSubscription, Attended: true, Beneficiaries: 2,
				}); err == nil {
					return errors.New("backed a multi-beneficiary session with a subscription credential")
				}
				return nil
			},
		},
	}
}

// Contracts returns the set of SECURITY contracts the conformance suite asserts, keyed to
// interface method. Phase 0 enumerates the four implemented seams; the remaining seams'
// contracts are added as their providers land (docs/ROADMAP.md).
func Contracts() []Contract {
	r := registry()
	cs := make([]Contract, len(r))
	for i, c := range r {
		cs[i] = c.contract
	}
	return cs
}

// RunContract runs the single registered contract for iface.method against put. It
// returns ErrProviderAbsent if no implementation was supplied for that interface (so the
// caller can skip), a descriptive error if the contract is violated, or nil if it holds.
func RunContract(ctx context.Context, put ProviderUnderTest, iface, method string) error {
	for _, c := range registry() {
		if c.contract.Interface == iface && c.contract.Method == method {
			if !c.present(put) {
				return ErrProviderAbsent
			}
			return c.run(ctx, put)
		}
	}
	return fmt.Errorf("testkit: no contract registered for %s.%s", iface, method)
}

// Run executes every registered contract whose provider was supplied and reports which
// were checked and which failed.
func Run(put ProviderUnderTest) Result {
	var res Result
	ctx := context.Background()
	for _, c := range registry() {
		if !c.present(put) {
			continue
		}
		res.Checked = append(res.Checked, c.contract)
		if err := c.run(ctx, put); err != nil {
			res.Failed = append(res.Failed, c.contract)
		}
	}
	return res
}

// Result is the outcome of a conformance Run: the contracts checked and which failed.
type Result struct {
	Checked []Contract
	Failed  []Contract
}
