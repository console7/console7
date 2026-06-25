package testkit

import (
	"bytes"
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

// confSubject is the canonical subject the conformance checks act as.
const confSubject = interfaces.Subject("conf-subject")

// confRepo is a registered repository the SCM checks target; confUnknownRepo is an
// unregistered one the PolicySoR fail-closed checks resolve.
var (
	confRepo        = interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	confUnknownRepo = interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "unregistered"}
)

func hasCloud(p ProviderUnderTest) bool     { return p.Cloud != nil }
func hasSecrets(p ProviderUnderTest) bool   { return p.Secrets != nil }
func hasIdentity(p ProviderUnderTest) bool  { return p.Identity != nil }
func hasSCM(p ProviderUnderTest) bool       { return p.SCM != nil }
func hasInference(p ProviderUnderTest) bool { return p.Inference != nil }
func hasPolicySoR(p ProviderUnderTest) bool { return p.PolicySoR != nil }
func hasEvidence(p ProviderUnderTest) bool  { return p.Evidence != nil }

// registry is the set of contracts the suite can assert. Seven seams have an
// implementation (Cloud, Secrets, Identity, SCM, Inference, PolicySoR, Evidence — the
// last three added with the Phase-1 orchestration spine); the remaining two
// (PolicyEngine, ObserveGateway) are asserted as their providers land in Phases 2–3
// (docs/ROADMAP.md), and until then their conformance cases skip.
func registry() []check {
	return []check{
		{Contract{"CloudProvider", "ProvisionSandbox", "reuse a sandbox across sessions, users, or personas"}, hasCloud, checkCloudProvisionSandbox},
		{Contract{"CloudProvider", "ApplyEgressPolicy", "widen egress beyond the provisioned allowlist, or fail open when a policy cannot be applied"}, hasCloud, checkCloudApplyEgressPolicy},
		{Contract{"CloudProvider", "DestroySandbox", "leave a destroyed sandbox operable, or otherwise make destruction reversible"}, hasCloud, checkCloudDestroySandbox},
		{Contract{"CloudProvider", "RunTask", "run a task outside a live, perimeter-intact sandbox, or sign off on a changed run with no commit digest"}, hasCloud, checkCloudRunTask},
		{Contract{"SecretsProvider", "MintEphemeral", "return long-lived or plaintext credential material to the control plane, or grant wider scope/TTL than requested"}, hasSecrets, checkSecretsMintEphemeral},
		{Contract{"SecretsProvider", "StoreSubscriptionToken", "store under a shared key, leave a standing operator read path, or pool the token"}, hasSecrets, checkSecretsStoreSubscriptionToken},
		{Contract{"SecretsProvider", "InjectSubscriptionToken", "return plaintext to the caller, inject into a non-owner sandbox, or back an unattended session"}, hasSecrets, checkSecretsInjectSubscriptionToken},
		{Contract{"SecretsProvider", "InjectOrgCredential", "return plaintext to the caller, inject into a non-owner / cross-session sandbox, or run the engine unauthenticated when no org credential is configured"}, hasSecrets, checkSecretsInjectOrgCredential},
		{Contract{"SecretsProvider", "InjectInferenceCredential", "return plaintext to the caller, inject into a non-owner / cross-session sandbox, or mint a credential that outlives the session"}, hasSecrets, checkSecretsInjectInferenceCredential},
		{Contract{"SecretsProvider", "RevokeSubject", "retain a recoverable copy of revoked material"}, hasSecrets, checkSecretsRevokeSubject},
		{Contract{"IdentityProvider", "Authenticate", "trust client-asserted claims without cryptographic verification, or mint/persist a long-lived session secret"}, hasIdentity, checkIdentityAuthenticate},
		{Contract{"IdentityProvider", "ResolveGroups", "let a subject self-assert or widen its own group membership"}, hasIdentity, checkIdentityResolveGroups},
		{Contract{"SCMProvider", "MintWorkingCredential", "issue a durable token, allow push beyond the working branch, or let the sandbox git client see long-lived material"}, hasSCM, checkSCMMintWorkingCredential},
		{Contract{"SCMProvider", "OpenPullRequest", "push to/merge a protected branch, or self-approve or actuate the change"}, hasSCM, checkSCMOpenPullRequest},
		{Contract{"SCMProvider", "FetchRepoBundle", "return a durable token or make the sandbox fetch from the SCM itself"}, hasSCM, checkSCMFetchRepoBundle},
		{Contract{"SCMProvider", "PushBranch", "push to a protected branch, push an empty bundle, or deliver the push credential to the sandbox"}, hasSCM, checkSCMPushBranch},
		{Contract{"InferenceBackend", "Resolve", "back an unattended or multi-beneficiary session with a subscription credential, or pool a subscription across beneficiaries"}, hasInference, checkInferenceResolve},
		{Contract{"PolicySoR", "ResolveRepo", "fail open to a permissive default on an unknown target, or derive tier/stratum from an in-repo file"}, hasPolicySoR, checkPolicySoRResolveRepo},
		{Contract{"PolicySoR", "ResolveResource", "let a permissive origin confer a stricter target's reach, or fail open on an unknown resource"}, hasPolicySoR, checkPolicySoRResolveResource},
		{Contract{"EvidenceSink", "Append", "order the chain by the caller's ObservedAt, or expose a non-monotonic / mutable record position"}, hasEvidence, checkEvidenceAppend},
		{Contract{"EvidenceSink", "Stream", "stream a record it never durably committed (streaming supplements, never replaces, the WORM append)"}, hasEvidence, checkEvidenceStream},
	}
}

func checkCloudProvisionSandbox(ctx context.Context, p ProviderUnderTest) error {
	spec := interfaces.SandboxSpec{
		SessionID: interfaces.SessionID("conf-session-a"),
		Subject:   confSubject,
		Persona:   interfaces.PersonaAuthor,
		Egress:    interfaces.EgressPolicy{Allowlist: []string{"https://approved.internal"}},
		MaxTTL:    time.Minute,
	}
	// A sandbox is never reused across sessions, users, OR personas: provision
	// four sandboxes that each differ from the base in exactly one of those
	// dimensions and require all handles to be distinct and non-empty. Varying only
	// the session (the original check) would let a provider that keys uniqueness by
	// session alone — but reuses a handle for a different user or persona — slip
	// through, violating the security clause.
	variants := []interfaces.SandboxSpec{
		spec,
		func() interfaces.SandboxSpec { s := spec; s.SessionID = "conf-session-b"; return s }(),
		func() interfaces.SandboxSpec {
			s := spec
			s.SessionID, s.Subject = "conf-session-u", interfaces.Subject("conf-other-subject")
			return s
		}(),
		func() interfaces.SandboxSpec {
			s := spec
			s.SessionID, s.Persona = "conf-session-p", interfaces.PersonaOperate
			return s
		}(),
	}
	seen := make(map[string]bool, len(variants))
	for i, v := range variants {
		h, err := p.Cloud.ProvisionSandbox(ctx, v)
		if err != nil {
			return fmt.Errorf("provision %d failed: %w", i, err)
		}
		if h.ID == "" {
			return errors.New("provisioned an empty sandbox handle")
		}
		if seen[h.ID] {
			return errors.New("reused one sandbox handle across distinct session/user/persona")
		}
		seen[h.ID] = true
		defer func(h interfaces.SandboxHandle) { _ = p.Cloud.DestroySandbox(ctx, h) }(h)
	}
	return nil
}

func checkCloudApplyEgressPolicy(ctx context.Context, p ProviderUnderTest) error {
	// Fail closed: applying a policy to an unknown handle must error, not
	// silently succeed against nothing.
	if err := p.Cloud.ApplyEgressPolicy(ctx, interfaces.SandboxHandle{ID: "no-such-sandbox"}, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}}); err == nil {
		return errors.New("applied egress to an unknown sandbox instead of failing closed")
	}
	h, err := p.Cloud.ProvisionSandbox(ctx, interfaces.SandboxSpec{
		SessionID: interfaces.SessionID("conf-egress"),
		Subject:   confSubject,
		Persona:   interfaces.PersonaAuthor,
		Egress:    interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}},
		MaxTTL:    time.Minute,
	})
	if err != nil {
		return fmt.Errorf("provision failed: %w", err)
	}
	defer func() { _ = p.Cloud.DestroySandbox(ctx, h) }()
	// Never widen: adding a destination beyond the provisioned (profile)
	// allowlist must be refused.
	if err := p.Cloud.ApplyEgressPolicy(ctx, h, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal", "https://b.internal"}}); err == nil {
		return errors.New("widened egress beyond the provisioned allowlist")
	}
	return nil
}

func checkCloudDestroySandbox(ctx context.Context, p ProviderUnderTest) error {
	h, err := p.Cloud.ProvisionSandbox(ctx, interfaces.SandboxSpec{
		SessionID: interfaces.SessionID("conf-destroy"),
		Subject:   confSubject,
		Persona:   interfaces.PersonaAuthor,
		Egress:    interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}},
		MaxTTL:    time.Minute,
	})
	if err != nil {
		return fmt.Errorf("provision failed: %w", err)
	}
	if err := p.Cloud.DestroySandbox(ctx, h); err != nil {
		return fmt.Errorf("destroy failed: %w", err)
	}
	// Irreversible: a destroyed sandbox cannot be destroyed again or operated on
	// — a second destroy or an egress change must fail closed, never resurrect it.
	if err := p.Cloud.DestroySandbox(ctx, h); err == nil {
		return errors.New("destroyed an already-destroyed sandbox (destruction is reversible)")
	}
	if err := p.Cloud.ApplyEgressPolicy(ctx, h, interfaces.EgressPolicy{Allowlist: nil}); err == nil {
		return errors.New("operated on a destroyed sandbox")
	}
	return nil
}

// checkCloudRunTask asserts the interface-observable half of the RunTask contract: a task runs
// ONLY inside a live, perimeter-intact sandbox, never after destruction, and a run reported as
// changed carries a non-empty commit digest the orchestrator can sign.
//
// SCOPE: the guarantees that are NOT observable through the interface — that the engine ran under
// the LOCKED managed-settings, that egress was not widened, that no transcript/secret leaked back —
// are asserted by providers/cloud-gcp's own white-box tests (it renders managed-settings before the
// exec and passes the prompt over stdin), not here, exactly like the SecretsProvider no-read-path
// guarantees (see the check-struct SCOPE note).
func checkCloudRunTask(ctx context.Context, p ProviderUnderTest) error {
	task := interfaces.EngineTask{
		SessionID: interfaces.SessionID("conf-run"),
		Profile:   interfaces.SessionProfile{Persona: interfaces.PersonaAuthor},
		Repo:      confRepo,
		Branch:    "feature/conf",
		Prompt:    "do the work described in the task",
		Timeout:   time.Minute,
	}
	// Fail closed: running a task in an unknown sandbox must error, not run against nothing.
	if _, err := p.Cloud.RunTask(ctx, interfaces.SandboxHandle{ID: "no-such-sandbox"}, task); err == nil {
		return errors.New("ran a task in an unknown sandbox instead of failing closed")
	}
	h, err := p.Cloud.ProvisionSandbox(ctx, interfaces.SandboxSpec{
		SessionID: task.SessionID,
		Subject:   confSubject,
		Persona:   interfaces.PersonaAuthor,
		Egress:    interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}},
		MaxTTL:    time.Minute,
	})
	if err != nil {
		return fmt.Errorf("provision failed: %w", err)
	}
	// A live sandbox runs the task, and a changed run must carry a non-empty digest to sign — a
	// provider cannot claim a change while returning a zero digest the orchestrator would sign blind.
	res, err := p.Cloud.RunTask(ctx, h, task)
	if err != nil {
		_ = p.Cloud.DestroySandbox(ctx, h)
		return fmt.Errorf("RunTask in a live sandbox errored: %w", err)
	}
	if res.Changed && len(res.CommitDigest) == 0 {
		_ = p.Cloud.DestroySandbox(ctx, h)
		return errors.New("reported a changed run with an empty commit digest")
	}
	// A changed run must also carry a non-empty CommitBundle — the working branch the control plane
	// pushes; a no-op run must NOT (nothing to push). Without this a provider could claim a change the
	// control-plane-side push has no payload for (cloud.go EngineResult.CommitBundle).
	if res.Changed && len(res.CommitBundle) == 0 {
		_ = p.Cloud.DestroySandbox(ctx, h)
		return errors.New("reported a changed run with an empty commit bundle (nothing for the control plane to push)")
	}
	if !res.Changed && len(res.CommitBundle) != 0 {
		_ = p.Cloud.DestroySandbox(ctx, h)
		return errors.New("a no-change run must return an empty commit bundle")
	}
	// No run after destroy: the load-bearing invariant — a task must never execute in a torn-down
	// (perimeter-gone) sandbox.
	if err := p.Cloud.DestroySandbox(ctx, h); err != nil {
		return fmt.Errorf("destroy failed: %w", err)
	}
	if _, err := p.Cloud.RunTask(ctx, h, task); err == nil {
		return errors.New("ran a task in a destroyed sandbox instead of failing closed")
	}
	return nil
}

func checkSecretsMintEphemeral(ctx context.Context, p ProviderUnderTest) error {
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
}

func checkSecretsStoreSubscriptionToken(ctx context.Context, p ProviderUnderTest) error {
	// Interface-observable: a valid token is accepted, and the interface
	// exposes no plaintext read path by construction. The per-user-key /
	// no-pooling invariant is asserted white-box (see check doc).
	if err := p.Secrets.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{
		Subject: confSubject, Token: []byte("conf-subscription-token"),
	}); err != nil {
		return fmt.Errorf("StoreSubscriptionToken with a valid token errored: %w", err)
	}
	return nil
}

func checkSecretsInjectSubscriptionToken(ctx context.Context, p ProviderUnderTest) error {
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
	return checkSecretsInjectWithRig(ctx, p)
}

// checkSecretsInjectWithRig exercises the attended/beneficiary/owner gate against
// a real owned sandbox supplied by the rig — split out so the rig-less and rigged
// paths each stay within the complexity bar.
func checkSecretsInjectWithRig(ctx context.Context, p ProviderUnderTest) error {
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
}

// checkSecretsInjectOrgCredential upholds InjectOrgCredential's SECURITY clause: the org credential
// is delivered ONLY into the session's own sandbox and never returned to the caller. Unlike a
// subscription token it has NO attended/beneficiary gate (it backs any org-API-lane session), so the
// only refusal exercised is ownership/cross-session. The org credential is configured by the
// conformance harness out-of-band (the provider's SetOrgCredential, off-seam); an UNCONFIGURED
// provider failing closed is asserted white-box per impl, since it is not configurable through the seam.
func checkSecretsInjectOrgCredential(ctx context.Context, p ProviderUnderTest) error {
	dummy := interfaces.SandboxHandle{ID: "conf-org-nonexistent-sandbox"}
	// Must refuse injection into a sandbox that is not this subject's session sandbox (fail closed).
	if err := p.Secrets.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{
		Subject: confSubject, SessionID: "conf-org", Sandbox: dummy,
	}); err == nil {
		return errors.New("injected the org credential into a non-owned sandbox")
	}
	// Without a rig the above only proves "some error"; with a rig, exercise delivery against REAL
	// owned/cross-session sandboxes and confirm the owned case succeeds.
	if p.SecretsRig == nil {
		return nil
	}
	const owner = interfaces.Subject("conf-org-owner")
	const session = interfaces.SessionID("conf-org-inject")
	owned := p.SecretsRig.Provision(owner, session)
	other := p.SecretsRig.Provision("conf-org-other", "conf-org-other-session")
	// A different session's sandbox must be refused (no cross-session delivery).
	if err := p.Secrets.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{
		Subject: owner, SessionID: session, Sandbox: other,
	}); err == nil {
		return errors.New("injected the org credential into a different session's sandbox")
	}
	// Injection into the session's OWN sandbox must succeed (the harness configured the org credential).
	if err := p.Secrets.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{
		Subject: owner, SessionID: session, Sandbox: owned,
	}); err != nil {
		return fmt.Errorf("org-credential injection into the session's own sandbox should succeed: %w", err)
	}
	return nil
}

// checkSecretsInjectInferenceCredential upholds InjectInferenceCredential's SECURITY clause: the
// MINTED inference credential is delivered ONLY for the session's own sandbox (to its auth-proxy
// gateway — the sandbox stays credential-free), capped to the session deadline, and never returned to
// the caller. It exercises the universal fail-closed cases (a
// past/zero deadline; a non-owner / cross-session sandbox) that hold regardless of how the minter is
// wired; the owned-success path is asserted white-box per impl (it needs the impl's minter — the real
// secrets-gcp provider is fail-closed until SetAccessTokenMinter, whereas the dev double mints inline).
func checkSecretsInjectInferenceCredential(ctx context.Context, p ProviderUnderTest) error {
	future := time.Now().Add(15 * time.Minute)
	dummy := interfaces.SandboxHandle{ID: "conf-inf-nonexistent-sandbox"}
	// A non-owned sandbox is refused (fail closed) even with a valid future deadline.
	if err := p.Secrets.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{
		Subject: confSubject, SessionID: "conf-inf", Sandbox: dummy, SessionDeadline: future,
	}); err == nil {
		return errors.New("injected an inference credential into a non-owned sandbox")
	}
	if p.SecretsRig == nil {
		return nil
	}
	const owner = interfaces.Subject("conf-inf-owner")
	const session = interfaces.SessionID("conf-inf-inject")
	owned := p.SecretsRig.Provision(owner, session)
	other := p.SecretsRig.Provision("conf-inf-other", "conf-inf-other-session")
	// A zero/past deadline is refused — never mint material that can outlive the session.
	if err := p.Secrets.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{
		Subject: owner, SessionID: session, Sandbox: owned, SessionDeadline: time.Time{},
	}); err == nil {
		return errors.New("minted an inference credential with no session deadline (could outlive the session)")
	}
	// A different session's sandbox is refused even with a valid deadline (no cross-session delivery).
	if err := p.Secrets.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{
		Subject: owner, SessionID: session, Sandbox: other, SessionDeadline: future,
	}); err == nil {
		return errors.New("injected an inference credential into a different session's sandbox")
	}
	// Injection into the session's OWN sandbox with a future deadline must succeed — proving the
	// refusals above came from the gate, not a uniformly-failing minter. (The harness wires a token
	// minter off-seam — the dev double mints inline, the GCP provider via SetAccessTokenMinter; a
	// minter-less provider is fail-closed and asserted white-box.)
	if err := p.Secrets.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{
		Subject: owner, SessionID: session, Sandbox: owned, SessionDeadline: future,
	}); err != nil {
		return fmt.Errorf("inference-credential injection into the session's own sandbox should succeed: %w", err)
	}
	return nil
}

func checkSecretsRevokeSubject(ctx context.Context, p ProviderUnderTest) error {
	// Interface-observable: revocation succeeds. Unrecoverability is not
	// probeable through the interface (no read path) and is asserted white-box.
	if err := p.Secrets.RevokeSubject(ctx, "conf-subject-to-revoke"); err != nil {
		return fmt.Errorf("RevokeSubject errored: %w", err)
	}
	return nil
}

func checkIdentityAuthenticate(ctx context.Context, p ProviderUnderTest) error {
	if _, err := p.Identity.Authenticate(ctx, "garbage-unverifiable-assertion"); err == nil {
		return errors.New("authenticated an unverifiable assertion")
	}
	return nil
}

func checkIdentityResolveGroups(ctx context.Context, p ProviderUnderTest) error {
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
}

func checkSCMMintWorkingCredential(ctx context.Context, p ProviderUnderTest) error {
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
}

func checkSCMOpenPullRequest(ctx context.Context, p ProviderUnderTest) error {
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
}

func checkSCMFetchRepoBundle(ctx context.Context, p ProviderUnderTest) error {
	// Must return non-empty content (a bundle) for a valid repo + base branch.
	b, err := p.SCM.FetchRepoBundle(ctx, confRepo, "main")
	if err != nil {
		return fmt.Errorf("FetchRepoBundle for a valid repo errored: %w", err)
	}
	if len(b) == 0 {
		return errors.New("FetchRepoBundle returned an empty bundle")
	}
	// Must fail closed on a missing base branch.
	if _, err := p.SCM.FetchRepoBundle(ctx, confRepo, ""); err == nil {
		return errors.New("FetchRepoBundle accepted an empty base branch")
	}
	return nil
}

func checkSCMPushBranch(ctx context.Context, p ProviderUnderTest) error {
	deadline := time.Now().Add(30 * time.Minute)
	// Must refuse a protected/default branch (the change is proposed via a PR, never pushed onto a
	// protected ref).
	if err := p.SCM.PushBranch(ctx, interfaces.PushBranchRequest{
		Subject: confSubject, SessionID: "conf", Repo: confRepo, Branch: "main",
		Bundle: []byte("b"), SessionDeadline: deadline,
	}); err == nil {
		return errors.New("pushed to the protected branch main")
	}
	// Must fail closed on an empty bundle (nothing to push).
	if err := p.SCM.PushBranch(ctx, interfaces.PushBranchRequest{
		Subject: confSubject, SessionID: "conf", Repo: confRepo, Branch: "feature/conf",
		Bundle: nil, SessionDeadline: deadline,
	}); err == nil {
		return errors.New("pushed an empty bundle")
	}
	// Must accept a valid working-branch push.
	if err := p.SCM.PushBranch(ctx, interfaces.PushBranchRequest{
		Subject: confSubject, SessionID: "conf", Repo: confRepo, Branch: "feature/conf",
		Bundle: []byte("working-branch-bundle"), SessionDeadline: deadline,
	}); err != nil {
		return fmt.Errorf("PushBranch for a valid working-branch push errored: %w", err)
	}
	return nil
}

func checkInferenceResolve(ctx context.Context, p ProviderUnderTest) error {
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
	// Any endpoint a backend DOES resolve MUST name its concrete lane (Kind): Mode alone cannot tell
	// a Vertex org route from a direct-Anthropic org route, and the CloudProvider needs the lane to
	// render the right engine env and credential type. This asserts IF org-API resolves — a backend
	// is free to refuse a route (a subscription-only backend may), so a refusal here is not a failure;
	// only resolving an endpoint WITHOUT a lane is.
	if ep, err := p.Inference.Resolve(ctx, interfaces.InferenceSelection{
		Mode: interfaces.ModeOrgAPI, Attended: false, Beneficiaries: 1,
	}); err == nil && ep.Kind == interfaces.BackendUnspecified {
		return errors.New("resolved a backend endpoint but left BackendKind unspecified — a consumer cannot tell the inference lane")
	}
	return nil
}

func checkPolicySoRResolveRepo(ctx context.Context, p ProviderUnderTest) error {
	ts, err := p.PolicySoR.ResolveRepo(ctx, confUnknownRepo)
	if err != nil {
		// Denying an unknown target by RETURNING AN ERROR is itself a valid
		// fail-closed response (the orchestrator treats it as deny). Either an
		// error or a most-restrictive coordinate conforms; only a permissive
		// resolution violates the contract.
		return nil
	}
	return assertFailClosedTarget("repo", ts)
}

func checkPolicySoRResolveResource(ctx context.Context, p ProviderUnderTest) error {
	ts, err := p.PolicySoR.ResolveResource(ctx, interfaces.ResourceRef{Kind: "service", ID: "unregistered"})
	if err != nil {
		return nil // fail-closed by error is acceptable (see ResolveRepo).
	}
	return assertFailClosedTarget("resource", ts)
}

func checkEvidenceAppend(ctx context.Context, p ProviderUnderTest) error {
	// Two records appended in order, the SECOND carrying an EARLIER ObservedAt,
	// prove the sink orders by its own append (monotonic Sequence + stamped
	// AppendedAt), never by the untrusted ObservedAt.
	early := time.Unix(0, 0).UTC()
	late := time.Unix(1<<31, 0).UTC()
	first, err := p.Evidence.Append(ctx, interfaces.EvidenceRecord{
		SessionID: "conf-session", Subject: confSubject, Persona: interfaces.PersonaAuthor,
		Type: "conf-1", ObservedAt: late, Payload: []byte("a"),
	})
	if err != nil {
		return fmt.Errorf("first append failed: %w", err)
	}
	second, err := p.Evidence.Append(ctx, interfaces.EvidenceRecord{
		SessionID: "conf-session", Subject: confSubject, Persona: interfaces.PersonaAuthor,
		Type: "conf-2", ObservedAt: early, Payload: []byte("b"),
	})
	if err != nil {
		return fmt.Errorf("second append failed: %w", err)
	}
	if second.Sequence <= first.Sequence {
		return fmt.Errorf("sequence not monotonic: first=%d second=%d", first.Sequence, second.Sequence)
	}
	if first.AppendedAt.IsZero() || second.AppendedAt.IsZero() {
		return errors.New("sink did not stamp its own AppendedAt")
	}
	if second.AppendedAt.Before(first.AppendedAt) {
		return errors.New("chain ordered by the caller's ObservedAt, not the sink's AppendedAt")
	}
	// Every appended record must carry its chain hash — the first as much as the
	// second, or the chain's anchor has no tamper-evidence link.
	if len(first.Hash) == 0 || len(second.Hash) == 0 {
		return errors.New("an appended record carries no chain hash")
	}
	if bytes.Equal(first.Hash, second.Hash) {
		return errors.New("records are not distinctly hash-chained")
	}
	return nil
}

func checkEvidenceStream(ctx context.Context, p ProviderUnderTest) error {
	ref, err := p.Evidence.Append(ctx, interfaces.EvidenceRecord{
		SessionID: "conf-session", Subject: confSubject, Persona: interfaces.PersonaAuthor,
		Type: "conf-stream", ObservedAt: time.Unix(0, 0).UTC(), Payload: []byte("c"),
	})
	if err != nil {
		return fmt.Errorf("append failed: %w", err)
	}
	// A committed record streams without error; Stream supplements the WORM
	// append, so the happy path must succeed.
	if err := p.Evidence.Stream(ctx, ref); err != nil {
		return fmt.Errorf("streaming a committed record failed: %w", err)
	}
	// Fail closed: a RecordRef the sink never committed (a forged/out-of-range
	// reference) must be rejected — you can only stream what was durably appended.
	if err := p.Evidence.Stream(ctx, interfaces.RecordRef{Sequence: 1 << 40}); err == nil {
		return errors.New("streamed an uncommitted record reference instead of failing closed")
	}
	// A ref naming an existing sequence but with a TAMPERED hash must also be
	// rejected — a RecordRef identifies the committed record by sequence AND hash,
	// so validating only the sequence would accept a forged reference.
	forged := interfaces.RecordRef{Sequence: ref.Sequence, AppendedAt: ref.AppendedAt, Hash: append([]byte(nil), ref.Hash...)}
	if len(forged.Hash) == 0 {
		forged.Hash = []byte{0x00}
	} else {
		forged.Hash[0] ^= 0xff
	}
	if err := p.Evidence.Stream(ctx, forged); err == nil {
		return errors.New("streamed a ref with a forged hash instead of failing closed")
	}
	return nil
}

// assertFailClosedTarget verifies a coordinate resolved for an UNKNOWN target is fail-closed
// on BOTH axes: the tier is at least as restrictive as Tier1 (admitting TierUnknown or a
// provider whose most-restrictive real tier is Tier1, rejecting any permissive Tier2..Tier4),
// and the stratum is the fail-closed default StratumUnknown (returning a known stratum for an
// unknown target would claim knowledge it does not have, certifying a partially-permissive
// profile). kind is "repo" or "resource" for the message.
func assertFailClosedTarget(kind string, ts interfaces.TierStratum) error {
	// The tier must be a KNOWN fail-closed coordinate — TierUnknown or Tier1. This rejects
	// permissive tiers (Tier2..Tier4) AND out-of-range garbage (e.g. Tier(99)), which would
	// otherwise rank as "most restrictive" via MoreRestrictiveThan and slip through even
	// though callers like ResolveProfile reject it — the suite must not certify it either.
	if ts.Tier != interfaces.TierUnknown && ts.Tier != interfaces.Tier1 {
		return fmt.Errorf("unknown %s resolved to tier %d, not a known fail-closed coordinate (TierUnknown or Tier1)", kind, ts.Tier)
	}
	if ts.Stratum != interfaces.StratumUnknown {
		return fmt.Errorf("unknown %s resolved to a non-fail-closed stratum (%d); expected StratumUnknown", kind, ts.Stratum)
	}
	return nil
}

// Contracts returns the set of SECURITY contracts the conformance suite asserts, keyed to
// interface method. Seven seams are enumerated today; the remaining two (PolicyEngine,
// ObserveGateway) are added as their providers land in Phases 2–3 (docs/ROADMAP.md).
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
