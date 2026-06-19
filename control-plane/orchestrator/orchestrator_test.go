package orchestrator_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/console7/console7/control-plane/orchestrator"
	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

const (
	subscriptionURL = "https://subscription.internal/inference"
	orgAPIURL       = "https://vertex.internal/inference"
)

// bench wires the in-memory seams the orchestration spine composes, mirroring the keybroker
// broker bench (keybroker/broker/broker_test.go) plus the cloud/evidence/policy seams this
// PR adds.
type bench struct {
	orch     *orchestrator.Orchestrator
	cloud    *devkit.MemCloud
	evidence *devkit.MemEvidence
	scm      *devkit.MemSCM
	caRoot   ed25519.PublicKey
	idpPriv  ed25519.PrivateKey
	repo     interfaces.RepoRef
}

func newBench(t *testing.T) bench {
	t.Helper()
	return newBenchWithAllowlist(t, []string{subscriptionURL, orgAPIURL})
}

func newBenchWithAllowlist(t *testing.T, allowlist []string) bench {
	t.Helper()
	reg := devkit.NewSandboxRegistry()
	cloud := devkit.NewMemCloud(reg)
	secrets := devkit.NewMemSecrets(reg)
	scm := devkit.NewMemSCM(15 * time.Minute)
	ca := signing.NewDevCA()
	binder := signing.NewNHIBinder(ca)

	idpPub, idpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("idp keygen: %v", err)
	}
	identity := devkit.NewDevIdentity(idpPub, nil)
	inference := devkit.NewPolicyInference(devkit.SeamPolicy{
		SubscriptionEndpoint: subscriptionURL,
		OrgAPIEndpoint:       orgAPIURL,
		SubscriptionEnabled:  true,
	})
	b := broker.New(identity, secrets, scm, inference, binder)

	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	sor := devkit.NewFixedPolicySoR(repo)
	evidence := devkit.NewMemEvidence()

	orch := orchestrator.New(b, cloud, evidence, sor, allowlist, 30*time.Minute)
	return bench{orch: orch, cloud: cloud, evidence: evidence, scm: scm, caRoot: ca.Root(), idpPriv: idpPriv, repo: repo}
}

func (b bench) authn(t *testing.T, subject interfaces.Subject) interfaces.AuthnToken {
	t.Helper()
	return devkit.IssueDevAssertion(b.idpPriv, subject, time.Now().Add(time.Hour))
}

// TestSpike_SessionLifecycle walks one governed task end to end on the bench: authenticate →
// resolve the fixed-T3 profile through the PolicySoR seam → mint NHI + creds → provision the
// sandbox with default-deny egress → resolve inference (on the allowlist) → inject the
// subscription token → sign the commit → open a PR (PR-only exit) → emit signed evidence at
// every step → teardown. It asserts the lineage (Subject → NHI → signed commit) and an
// unbroken, verifiable evidence chain.
func TestSpike_SessionLifecycle(t *testing.T) {
	b := newBench(t)
	ctx := context.Background()

	sum, err := b.orch.Run(ctx, orchestrator.LaunchRequest{
		Authn:        b.authn(t, "alice"),
		SessionID:    "sess-1",
		Persona:      interfaces.PersonaAuthor,
		Repo:         b.repo,
		Branch:       "feature/x",
		Attended:     true,
		Subscription: []byte("alice-subscription-token"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Lineage anchor + per-session NHI.
	if sum.Subject != "alice" {
		t.Errorf("subject = %q, want alice", sum.Subject)
	}
	if sum.NHI != "nhi/sess-1/author" {
		t.Errorf("NHI = %q, want nhi/sess-1/author", sum.NHI)
	}

	// Attended single-user → subscription-backed inference, and it is on the allowlist.
	if sum.Inference.Mode != interfaces.ModeSubscription || sum.Inference.URL != subscriptionURL {
		t.Errorf("inference = %+v, want subscription %q", sum.Inference, subscriptionURL)
	}

	// Sandbox torn down by teardown — never left live.
	if b.cloud.Live(sum.Sandbox) {
		t.Error("sandbox still live after the session ended")
	}

	// Exactly one PR opened; nothing merged or actuated.
	if got := b.scm.OpenPRCount(); got != 1 {
		t.Errorf("OpenPRCount = %d, want 1", got)
	}
	if sum.PR.URL == "" && sum.PR.Number == 0 {
		t.Error("expected a non-empty PR reference")
	}

	// The crypto-attested output: the commit signature verifies the full lineage chain.
	if err := signing.Verify(b.caRoot, sum.CommitDigest, sum.CommitSig); err != nil {
		t.Errorf("commit signature does not verify: %v", err)
	}
	if sum.CommitSig.Subject != "alice" {
		t.Errorf("commit signature subject = %q, want alice", sum.CommitSig.Subject)
	}

	// The evidence chain is unbroken, and every record carries verifiable Subject → NHI
	// lineage. Expected lifecycle events, in order.
	if err := b.evidence.VerifyChain(); err != nil {
		t.Errorf("evidence chain broken: %v", err)
	}
	wantEvents := []string{
		"session-start", "sandbox-provisioned", "inference-resolved", "egress-narrowed",
		"subscription-injected", "commit-signed", "pr-opened", "session-end",
	}
	if b.evidence.Len() != len(wantEvents) {
		t.Fatalf("evidence has %d records, want %d", b.evidence.Len(), len(wantEvents))
	}
	if sum.Records != len(wantEvents) {
		t.Errorf("summary Records = %d, want %d", sum.Records, len(wantEvents))
	}
	for i, want := range wantEvents {
		rec, _, ok := b.evidence.At(i)
		if !ok {
			t.Fatalf("missing evidence record %d", i)
		}
		if rec.Type != want {
			t.Errorf("record %d type = %q, want %q", i, rec.Type, want)
		}
		if rec.Subject != "alice" {
			t.Errorf("record %d subject = %q, want alice", i, rec.Subject)
		}
		if err := orchestrator.VerifyRecordPayload(b.caRoot, rec); err != nil {
			t.Errorf("record %d (%s) lineage signature does not verify: %v", i, rec.Type, err)
		}
	}
}

// TestRun_UnknownRepoFailsClosed: a target the PolicySoR does not recognise resolves to the
// most-restrictive tier, so no profile is produced and the session must not launch.
func TestRun_UnknownRepoFailsClosed(t *testing.T) {
	b := newBench(t)
	_, err := b.orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn:     b.authn(t, "alice"),
		SessionID: "sess-2",
		Persona:   interfaces.PersonaAuthor,
		Repo:      interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "unregistered"},
		Branch:    "feature/x",
		Attended:  true,
	})
	if err == nil {
		t.Fatal("expected Run to fail closed on an unresolved target")
	}
	// Nothing should have been provisioned or recorded for a session that never launched.
	if b.evidence.Len() != 0 {
		t.Errorf("expected no evidence for a fail-closed launch, got %d records", b.evidence.Len())
	}
	if b.scm.OpenPRCount() != 0 {
		t.Error("expected no PR for a fail-closed launch")
	}
}

// TestRun_UnattendedRoutesOrgAPI: an unattended launch routes to the org API, never the
// subscription, and runs the full lifecycle without injecting a subscription token.
func TestRun_UnattendedRoutesOrgAPI(t *testing.T) {
	b := newBench(t)
	sum, err := b.orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn:     b.authn(t, "bob"),
		SessionID: "sess-3",
		Persona:   interfaces.PersonaAuthor,
		Repo:      b.repo,
		Branch:    "feature/y",
		Attended:  false,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.Inference.Mode != interfaces.ModeOrgAPI || sum.Inference.URL != orgAPIURL {
		t.Errorf("inference = %+v, want org API %q", sum.Inference, orgAPIURL)
	}
	// No subscription-injected event for an unattended session.
	for i := 0; i < b.evidence.Len(); i++ {
		rec, _, _ := b.evidence.At(i)
		if rec.Type == "subscription-injected" {
			t.Error("unattended session injected a subscription token")
		}
	}
}

// TestVerifyRecordPayload_RejectsTamperedAttribution proves the per-record lineage
// signature binds the record's OWN Subject/SessionID columns: altering the attribution an
// auditor reads off a record (or replaying a genuine payload onto a record with a different
// subject) breaks verification, even though the embedded signature is itself a valid one.
func TestVerifyRecordPayload_RejectsTamperedAttribution(t *testing.T) {
	b := newBench(t)
	if _, err := b.orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn: b.authn(t, "alice"), SessionID: "sess-5", Persona: interfaces.PersonaAuthor,
		Repo: b.repo, Branch: "feature/x", Attended: true, Subscription: []byte("tok"),
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	rec, _, ok := b.evidence.At(0)
	if !ok {
		t.Fatal("no evidence record to tamper")
	}
	// Sanity: the untampered record verifies.
	if err := orchestrator.VerifyRecordPayload(b.caRoot, rec); err != nil {
		t.Fatalf("untampered record should verify: %v", err)
	}
	// Tamper the attribution column (the signature itself is unchanged and valid in
	// isolation) — verification must reject it.
	rec.Subject = "mallory"
	if err := orchestrator.VerifyRecordPayload(b.caRoot, rec); err == nil {
		t.Error("expected verification to reject a record whose Subject column was altered")
	}
}

// TestRun_InferenceEndpointOffAllowlistFailsClosed: if the resolved inference endpoint is
// not on the session's egress allowlist, the boundary is authoritative — the session aborts
// (and the sandbox is torn down) rather than running against an endpoint the perimeter would
// deny. Guards the egress check from being silently dropped.
func TestRun_InferenceEndpointOffAllowlistFailsClosed(t *testing.T) {
	// Allowlist deliberately excludes orgAPIURL, the endpoint an unattended session resolves.
	b := newBenchWithAllowlist(t, []string{"https://only-this.internal/inference"})
	_, err := b.orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn:     b.authn(t, "carol"),
		SessionID: "sess-4",
		Persona:   interfaces.PersonaAuthor,
		Repo:      b.repo,
		Branch:    "feature/z",
		Attended:  false,
	})
	if err == nil {
		t.Fatal("expected Run to fail closed when the resolved endpoint is off the allowlist")
	}
	// The session must have been torn down and never reached a PR.
	if b.scm.OpenPRCount() != 0 {
		t.Error("a fail-closed session must not open a PR")
	}
	var aborted bool
	for i := 0; i < b.evidence.Len(); i++ {
		rec, _, _ := b.evidence.At(i)
		if rec.Type == "session-aborted" {
			aborted = true
		}
		if rec.Type == "egress-narrowed" {
			t.Error("egress was narrowed despite the endpoint being off the allowlist")
		}
	}
	if !aborted {
		t.Error("expected a session-aborted evidence record on the fail-closed path")
	}
}
