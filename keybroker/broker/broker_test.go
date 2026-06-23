package broker_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

// bench wires the in-memory devkit seams into a real Broker — the Phase-0 bench harness.
type bench struct {
	broker  *broker.Broker
	reg     *devkit.SandboxRegistry
	caRoot  ed25519.PublicKey
	idpPriv ed25519.PrivateKey
}

func newBench(t *testing.T) *bench {
	t.Helper()
	reg := devkit.NewSandboxRegistry()
	secrets := devkit.NewMemSecrets(reg)
	scm := devkit.NewMemSCM(15 * time.Minute)
	ca := signing.NewDevCA()
	binder := signing.NewNHIBinder(ca)

	idpPub, idpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("idp keygen: %v", err)
	}
	id := devkit.NewDevIdentity(idpPub, map[interfaces.Subject][]interfaces.Group{"alice": {"eng"}})
	inference := devkit.NewPolicyInference(devkit.SeamPolicy{
		SubscriptionEndpoint: "https://subscription.internal/inference",
		OrgAPIEndpoint:       "https://vertex.internal/inference",
		SubscriptionEnabled:  true,
	})

	return &bench{
		broker:  broker.New(id, secrets, scm, inference, binder),
		reg:     reg,
		caRoot:  ca.Root(),
		idpPriv: idpPriv,
	}
}

// TestSpike_LoginToSignedAction is the Phase-0 exit demonstration: the credential /
// identity / seam behaviour, end to end on a bench. It walks login -> mint NHI + cloud +
// SCM creds -> store + inject subscription into the owner's sandbox -> route inference
// (attended vs unattended) -> sign a commit and verify the lineage.
func TestSpike_LoginToSignedAction(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()
	deadline := time.Now().Add(30 * time.Minute)

	// 1. Login: a verified SSO assertion -> a session identity with ephemeral creds.
	authn := devkit.IssueDevAssertion(b.idpPriv, "alice", time.Now().Add(time.Hour))
	minted, err := b.broker.MintSessionIdentity(ctx, broker.SessionRequest{
		Authn:           authn,
		SessionID:       "s1",
		Persona:         interfaces.PersonaAuthor,
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		Scopes:          []string{"repo:read", "repo:write:feature/x"},
		TTL:             1 * time.Hour,
		SessionDeadline: deadline,
	})
	if err != nil {
		t.Fatalf("MintSessionIdentity: %v", err)
	}
	if minted.Identity.Subject != "alice" {
		t.Errorf("subject = %q, want alice", minted.Identity.Subject)
	}
	if minted.Identity.Credential.Ref == "" {
		t.Error("cloud credential ref is empty")
	}
	if minted.Identity.Credential.Expiry.After(deadline) {
		t.Errorf("cloud credential outlives the session: %v > %v", minted.Identity.Credential.Expiry, deadline)
	}
	if minted.SCM.Ref == "" {
		t.Error("SCM credential ref is empty")
	}
	if minted.NHI != "nhi/s1/author" {
		t.Errorf("NHI = %q, want nhi/s1/author", minted.NHI)
	}

	// 2. Subscription vault: store the user's token, provision their sandbox, inject.
	token := []byte("alice-subscription-oauth-token")
	if err := b.broker.StoreSubscription(ctx, "alice", token); err != nil {
		t.Fatalf("StoreSubscription: %v", err)
	}
	aliceBox := b.reg.Provision("alice", "s1")
	if err := b.broker.InjectSubscription(ctx, interfaces.SubscriptionInjection{
		Subject:       "alice",
		SessionID:     "s1",
		Sandbox:       aliceBox,
		Attended:      true,
		Beneficiaries: 1,
	}); err != nil {
		t.Fatalf("InjectSubscription: %v", err)
	}
	got, ok := b.reg.Injected(aliceBox)
	if !ok || !bytes.Equal(got, token) {
		t.Errorf("subscription token not injected into owner sandbox: ok=%v", ok)
	}

	// 3. Inference routing: attended single-beneficiary stays on subscription; the same
	// session run unattended routes to org-API.
	attended, err := b.broker.ResolveInference(ctx, interfaces.InferenceSelection{
		SessionID: "s1", Subject: "alice", Mode: interfaces.ModeSubscription, Attended: true, Beneficiaries: 1,
	})
	if err != nil {
		t.Fatalf("ResolveInference (attended): %v", err)
	}
	if attended.Mode != interfaces.ModeSubscription {
		t.Errorf("attended session routed to %v, want subscription", attended.Mode)
	}
	orgAPI, err := b.broker.ResolveInference(ctx, interfaces.InferenceSelection{
		SessionID: "s1", Subject: "alice", Mode: interfaces.ModeOrgAPI, Attended: false, Beneficiaries: 1,
	})
	if err != nil {
		t.Fatalf("ResolveInference (unattended): %v", err)
	}
	if orgAPI.Mode != interfaces.ModeOrgAPI {
		t.Errorf("unattended session routed to %v, want org-API", orgAPI.Mode)
	}

	// 4. Signed action: the NHI signs a commit via the broker (the key never leaves it);
	// the lineage Subject->NHI->signature verifies against the CA root.
	commitDigest := []byte("sha256:deadbeef-commit")
	sig, err := b.broker.SignSession(ctx, "s1", commitDigest)
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	if err := signing.Verify(b.caRoot, commitDigest, sig); err != nil {
		t.Errorf("commit lineage failed to verify: %v", err)
	}
	if sig.Subject != "alice" {
		t.Errorf("signed commit lineage subject = %q, want alice", sig.Subject)
	}

	// 5. After release, the session's key can no longer sign — signatures cannot outlive
	// the session.
	b.broker.ReleaseSession("s1")
	if _, err := b.broker.SignSession(ctx, "s1", commitDigest); err == nil {
		t.Error("signed with a released session key")
	}
}

// TestMintSessionIdentity_FailedMintLeavesNoSigner: if credential minting fails after the
// NHI is bound (here, a protected-branch SCM mint), no signer is registered — a session
// that never launched cannot sign.
func TestMintSessionIdentity_FailedMintLeavesNoSigner(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()
	authn := devkit.IssueDevAssertion(b.idpPriv, "alice", time.Now().Add(time.Hour))
	_, err := b.broker.MintSessionIdentity(ctx, broker.SessionRequest{
		Authn:           authn,
		SessionID:       "s1",
		Persona:         interfaces.PersonaAuthor,
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "main", // protected: MintWorkingCredential fails.
		TTL:             time.Hour,
		SessionDeadline: time.Now().Add(30 * time.Minute),
	})
	if err == nil {
		t.Fatal("expected mint to fail on a protected branch")
	}
	if _, err := b.broker.SignSession(ctx, "s1", []byte("x")); err == nil {
		t.Error("a session whose mint failed must have no live signer")
	}
}

// TestMintSessionIdentity_RejectsDuplicateSession: a second mint for a live session ID is
// refused rather than silently clobbering the first session's signer.
func TestMintSessionIdentity_RejectsDuplicateSession(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()
	req := broker.SessionRequest{
		Authn:           devkit.IssueDevAssertion(b.idpPriv, "alice", time.Now().Add(time.Hour)),
		SessionID:       "s1",
		Persona:         interfaces.PersonaAuthor,
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		TTL:             time.Hour,
		SessionDeadline: time.Now().Add(30 * time.Minute),
	}
	if _, err := b.broker.MintSessionIdentity(ctx, req); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	req.Authn = devkit.IssueDevAssertion(b.idpPriv, "alice", time.Now().Add(time.Hour))
	if _, err := b.broker.MintSessionIdentity(ctx, req); err == nil {
		t.Error("expected a duplicate live session ID to be rejected")
	}
}

// countingSecrets counts MintEphemeral calls, to prove a rejected duplicate session never
// reaches credential issuance.
func TestBroker_InjectOrgCredential(t *testing.T) {
	reg := devkit.NewSandboxRegistry()
	secrets := devkit.NewMemSecrets(reg)
	orgKey := []byte("org-api-key")
	if err := secrets.SetOrgCredential(orgKey); err != nil {
		t.Fatalf("SetOrgCredential: %v", err)
	}
	ca := signing.NewDevCA()
	b := broker.New(devkit.NewDevIdentity(nil, nil), secrets, devkit.NewMemSCM(time.Minute),
		devkit.NewPolicyInference(devkit.SeamPolicy{}), signing.NewNHIBinder(ca))
	ctx := context.Background()
	box := reg.Provision("alice", "s1")

	// The broker forwards the facts; the seam delivers the org credential into the owning sandbox.
	if err := b.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: box}); err != nil {
		t.Fatalf("InjectOrgCredential: %v", err)
	}
	got, ok := reg.Injected(box)
	if !ok || !bytes.Equal(got, orgKey) {
		t.Errorf("org credential not injected into the owning sandbox: ok=%v", ok)
	}

	// A broker missing the secrets seam fails closed (an error, never a panic).
	nob := broker.New(devkit.NewDevIdentity(nil, nil), nil, devkit.NewMemSCM(time.Minute),
		devkit.NewPolicyInference(devkit.SeamPolicy{}), signing.NewNHIBinder(ca))
	if err := nob.InjectOrgCredential(ctx, interfaces.OrgCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: box}); err == nil {
		t.Error("broker missing the secrets seam should fail closed")
	}
}

func TestBroker_InjectInferenceCredential(t *testing.T) {
	reg := devkit.NewSandboxRegistry()
	secrets := devkit.NewMemSecrets(reg)
	ca := signing.NewDevCA()
	b := broker.New(devkit.NewDevIdentity(nil, nil), secrets, devkit.NewMemSCM(time.Minute),
		devkit.NewPolicyInference(devkit.SeamPolicy{}), signing.NewNHIBinder(ca))
	ctx := context.Background()
	box := reg.Provision("alice", "s1")
	deadline := time.Now().Add(15 * time.Minute)

	// The broker forwards the facts; the seam mints + delivers a (fake) inference credential into the owner.
	if err := b.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: box, SessionDeadline: deadline}); err != nil {
		t.Fatalf("InjectInferenceCredential: %v", err)
	}
	if _, ok := reg.Injected(box); !ok {
		t.Error("inference credential not injected into the owning sandbox")
	}

	// A broker missing the secrets seam fails closed (an error, never a panic).
	nob := broker.New(devkit.NewDevIdentity(nil, nil), nil, devkit.NewMemSCM(time.Minute),
		devkit.NewPolicyInference(devkit.SeamPolicy{}), signing.NewNHIBinder(ca))
	if err := nob.InjectInferenceCredential(ctx, interfaces.InferenceCredentialInjection{Subject: "alice", SessionID: "s1", Sandbox: box, SessionDeadline: deadline}); err == nil {
		t.Error("broker missing the secrets seam should fail closed")
	}
}

type countingSecrets struct {
	interfaces.SecretsProvider
	mints int
}

func (c *countingSecrets) MintEphemeral(ctx context.Context, req interfaces.EphemeralRequest) (interfaces.CredentialRef, error) {
	c.mints++
	return c.SecretsProvider.MintEphemeral(ctx, req)
}

// TestMintSessionIdentity_DuplicateMintsNoCredentials: a duplicate session ID is rejected at
// the reservation BEFORE any credential is minted, so the loser leaves no orphaned creds.
func TestMintSessionIdentity_DuplicateMintsNoCredentials(t *testing.T) {
	reg := devkit.NewSandboxRegistry()
	cs := &countingSecrets{SecretsProvider: devkit.NewMemSecrets(reg)}
	ca := signing.NewDevCA()
	idpPub, idpPriv, _ := ed25519.GenerateKey(nil)
	b := broker.New(devkit.NewDevIdentity(idpPub, nil), cs, devkit.NewMemSCM(15*time.Minute),
		devkit.NewPolicyInference(devkit.SeamPolicy{}), signing.NewNHIBinder(ca))
	req := broker.SessionRequest{
		Authn:           devkit.IssueDevAssertion(idpPriv, "alice", time.Now().Add(time.Hour)),
		SessionID:       "s1",
		Persona:         interfaces.PersonaAuthor,
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		TTL:             time.Hour,
		SessionDeadline: time.Now().Add(30 * time.Minute),
	}
	if _, err := b.MintSessionIdentity(context.Background(), req); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	req.Authn = devkit.IssueDevAssertion(idpPriv, "alice", time.Now().Add(time.Hour))
	if _, err := b.MintSessionIdentity(context.Background(), req); err == nil {
		t.Fatal("expected duplicate session to be rejected")
	}
	if cs.mints != 1 {
		t.Errorf("duplicate minted %d ephemeral creds; want 1 (the loser must not reach minting)", cs.mints)
	}
}

// TestSignSession_RefusesAfterDeadline: the NHI signer is refused once the session's hard
// deadline passes, even if ReleaseSession has not run — signatures cannot outlive the session.
func TestSignSession_RefusesAfterDeadline(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()
	if _, err := b.broker.MintSessionIdentity(ctx, broker.SessionRequest{
		Authn:           devkit.IssueDevAssertion(b.idpPriv, "alice", time.Now().Add(time.Hour)),
		SessionID:       "s1",
		Persona:         interfaces.PersonaAuthor,
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		TTL:             time.Hour,
		SessionDeadline: time.Now().Add(150 * time.Millisecond),
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	// Within the deadline, signing works.
	if _, err := b.broker.SignSession(ctx, "s1", []byte("x")); err != nil {
		t.Fatalf("expected signing within the deadline: %v", err)
	}
	time.Sleep(250 * time.Millisecond) // past the 150ms deadline
	if _, err := b.broker.SignSession(ctx, "s1", []byte("x")); err == nil {
		t.Error("signed past the session deadline (signer outlived the session)")
	}
}

// TestSpike_RejectsForgedLogin confirms an unverifiable SSO assertion never yields a
// credentialed session — the broker mints nothing on a failed authenticate.
func TestSpike_RejectsForgedLogin(t *testing.T) {
	b := newBench(t)
	_, attacker, _ := ed25519.GenerateKey(nil)
	forged := devkit.IssueDevAssertion(attacker, "alice", time.Now().Add(time.Hour))
	if _, err := b.broker.MintSessionIdentity(context.Background(), broker.SessionRequest{
		Authn:           forged,
		SessionID:       "s1",
		Persona:         interfaces.PersonaAuthor,
		Branch:          "feature/x",
		TTL:             time.Hour,
		SessionDeadline: time.Now().Add(time.Hour),
	}); err == nil {
		t.Error("minted a session from a forged SSO assertion")
	}
}
