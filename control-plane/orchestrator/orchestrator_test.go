package orchestrator_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/control-plane/evidence"
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
// broker bench (keybroker/broker/broker_test.go) plus the cloud/policy seams and the REAL
// control-plane evidence sink (the orchestrator's default sink; the devkit MemEvidence double
// is exercised by the standalone tests below).
type bench struct {
	orch     *orchestrator.Orchestrator
	cloud    *devkit.MemCloud
	evidence *evidence.Sink
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
	// The adopter's shared org API credential, configured out-of-band — the org-API lane injects it
	// into the sandbox (the control plane never carries its plaintext through the seam).
	if err := secrets.SetOrgCredential([]byte("org-api-key-fixture")); err != nil {
		t.Fatalf("set org credential: %v", err)
	}
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
	// The real control-plane evidence sink, signing checkpoints through a keybroker-minted sink
	// signer off the SAME DevCA the lineage binder uses (one trust root). ckptEvery=0 ⇒ the
	// orchestrator seals one checkpoint per session at session-end/teardown.
	sinkSigner, err := signing.NewSinkSigner(ca, "spike-evidence-sink")
	if err != nil {
		t.Fatalf("sink signer: %v", err)
	}
	sink := evidence.NewInMemory(sinkSigner, ca.Root(), 0)

	orch := orchestrator.New(b, cloud, sink, sor, allowlist, 30*time.Minute)
	return bench{orch: orch, cloud: cloud, evidence: sink, scm: scm, caRoot: ca.Root(), idpPriv: idpPriv, repo: repo}
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

	// Out-of-band login: the user's subscription token is vaulted under their key BEFORE the
	// session runs. The orchestrator never sees the plaintext — it only opts the session in.
	if err := b.orch.Broker.StoreSubscription(ctx, "alice", []byte("alice-subscription-token")); err != nil {
		t.Fatalf("StoreSubscription: %v", err)
	}

	sum, err := b.orch.Run(ctx, orchestrator.LaunchRequest{
		Authn:           b.authn(t, "alice"),
		SessionID:       "sess-1",
		Persona:         interfaces.PersonaAuthor,
		Repo:            b.repo,
		Branch:          "feature/x",
		Attended:        true,
		UseSubscription: true,
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
	// The sink sealed at least one checkpoint at session-end, and the checkpoints verify under
	// the CA root — the WORM head is sink-signed, not merely hash-chained.
	if len(b.evidence.Checkpoints()) == 0 {
		t.Error("expected at least one sink-signed checkpoint sealing the session")
	}
	if err := b.evidence.VerifyCheckpoints(b.caRoot, b.evidence.SinkID()); err != nil {
		t.Errorf("evidence checkpoints do not verify: %v", err)
	}
	wantEvents := []string{
		"session-start", "sandbox-provisioned", "inference-resolved", "egress-narrowed",
		"subscription-injected", "commit-signed", "pr-opening", "pr-opened", "session-end",
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
	// The org-API lane injects the org credential (never a subscription token) for an unattended session.
	var sawOrg, sawSub bool
	for i := 0; i < b.evidence.Len(); i++ {
		rec, _, _ := b.evidence.At(i)
		switch rec.Type {
		case "subscription-injected":
			sawSub = true
		case "org-credential-injected":
			sawOrg = true
		}
	}
	if sawSub {
		t.Error("unattended session injected a subscription token")
	}
	if !sawOrg {
		t.Error("unattended (org-API) session did not inject the org credential")
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
		Repo: b.repo, Branch: "feature/x", Attended: false,
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

// stubSoR returns a fixed TierStratum for any target — used to feed ResolveProfile
// out-of-range coordinates a real adapter might decode from bad registry data.
type stubSoR struct{ ts interfaces.TierStratum }

func (s stubSoR) ResolveRepo(context.Context, interfaces.RepoRef) (interfaces.TierStratum, error) {
	return s.ts, nil
}
func (s stubSoR) ResolveResource(context.Context, interfaces.ResourceRef) (interfaces.TierStratum, error) {
	return s.ts, nil
}

// TestResolveProfile_RejectsOutOfRangeCoordinates: a tier/stratum outside the known enum
// (e.g. a bad registry decode yielding Tier(99)) must fail closed, not yield a runnable
// profile.
func TestResolveProfile_RejectsOutOfRangeCoordinates(t *testing.T) {
	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	for _, ts := range []interfaces.TierStratum{
		{Tier: interfaces.Tier(99), Stratum: interfaces.Stratum1},
		{Tier: interfaces.Tier3, Stratum: interfaces.Stratum(99)},
	} {
		if _, err := orchestrator.ResolveProfile(context.Background(), stubSoR{ts}, repo, interfaces.PersonaAuthor, []string{"https://x"}, time.Minute); err == nil {
			t.Errorf("expected fail-closed on out-of-range coordinate %+v", ts)
		}
	}
}

// TestResolveProfile_RejectsNonT3S1Lane: Phase 1 supports exactly author × T3/S1; any other
// KNOWN coordinate (e.g. Tier1 or Stratum5) fails closed until the policy matrix exists.
func TestResolveProfile_RejectsNonT3S1Lane(t *testing.T) {
	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	for _, ts := range []interfaces.TierStratum{
		{Tier: interfaces.Tier1, Stratum: interfaces.Stratum1},
		{Tier: interfaces.Tier3, Stratum: interfaces.Stratum5},
		{Tier: interfaces.Tier4, Stratum: interfaces.Stratum1},
	} {
		if _, err := orchestrator.ResolveProfile(context.Background(), stubSoR{ts}, repo, interfaces.PersonaAuthor, []string{"https://x"}, time.Minute); err == nil {
			t.Errorf("expected fail-closed outside the T3/S1 lane for %+v", ts)
		}
	}
	if _, err := orchestrator.ResolveProfile(context.Background(), stubSoR{interfaces.TierStratum{Tier: interfaces.Tier3, Stratum: interfaces.Stratum1}}, repo, interfaces.PersonaAuthor, []string{"https://x"}, time.Minute); err != nil {
		t.Errorf("the supported T3/S1 lane should resolve: %v", err)
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

// failingDestroyCloud wraps a CloudProvider but always fails teardown, to prove the abort
// path surfaces (never swallows) a destroy failure.
type failingDestroyCloud struct{ interfaces.CloudProvider }

func (failingDestroyCloud) DestroySandbox(context.Context, interfaces.SandboxHandle) error {
	return errors.New("simulated destroy failure")
}

// countingSink wraps MemEvidence and counts Stream calls, to prove every appended record is
// also forwarded to the SIEM hook.
type countingSink struct {
	*devkit.MemEvidence
	streams int
}

func (s *countingSink) Stream(ctx context.Context, ref interfaces.RecordRef) error {
	s.streams++
	return s.MemEvidence.Stream(ctx, ref)
}

// TestRun_MissingBrokerSeamFailsClosedBeforeProvision: a broker missing a required sub-seam
// (here, Inference) is rejected up front — before any sandbox is provisioned — rather than
// panicking mid-session and leaking a sandbox.
func TestRun_MissingBrokerSeamFailsClosedBeforeProvision(t *testing.T) {
	reg := devkit.NewSandboxRegistry()
	ca := signing.NewDevCA()
	idpPub, idpPriv, _ := ed25519.GenerateKey(nil)
	// Inference seam is nil.
	b := broker.New(devkit.NewDevIdentity(idpPub, nil), devkit.NewMemSecrets(reg), devkit.NewMemSCM(15*time.Minute), nil, signing.NewNHIBinder(ca))
	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	cloud := devkit.NewMemCloud(reg)
	evidence := devkit.NewMemEvidence()
	orch := orchestrator.New(b, cloud, evidence, devkit.NewFixedPolicySoR(repo), []string{orgAPIURL}, 30*time.Minute)

	_, err := orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn:     devkit.IssueDevAssertion(idpPriv, "alice", time.Now().Add(time.Hour)),
		SessionID: "s1", Persona: interfaces.PersonaAuthor, Repo: repo, Branch: "feature/x",
	})
	if err == nil {
		t.Fatal("expected Run to fail closed on a broker missing a seam")
	}
	if evidence.Len() != 0 {
		t.Errorf("expected nothing provisioned/recorded before the seam check, got %d records", evidence.Len())
	}
}

// TestRun_AbortSurfacesTeardownFailure: when a post-provision stage fails AND teardown also
// fails, the returned error carries both — a possibly-still-live sandbox is never hidden.
func TestRun_AbortSurfacesTeardownFailure(t *testing.T) {
	reg := devkit.NewSandboxRegistry()
	ca := signing.NewDevCA()
	idpPub, idpPriv, _ := ed25519.GenerateKey(nil)
	b := broker.New(
		devkit.NewDevIdentity(idpPub, nil), devkit.NewMemSecrets(reg), devkit.NewMemSCM(15*time.Minute),
		devkit.NewPolicyInference(devkit.SeamPolicy{SubscriptionEndpoint: subscriptionURL, OrgAPIEndpoint: orgAPIURL, SubscriptionEnabled: true}),
		signing.NewNHIBinder(ca),
	)
	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	cloud := failingDestroyCloud{devkit.NewMemCloud(reg)}
	// Allowlist excludes orgAPIURL, so an unattended run aborts at egress-check after provision.
	orch := orchestrator.New(b, cloud, devkit.NewMemEvidence(), devkit.NewFixedPolicySoR(repo), []string{"https://only.internal"}, 30*time.Minute)

	_, err := orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn:     devkit.IssueDevAssertion(idpPriv, "alice", time.Now().Add(time.Hour)),
		SessionID: "s1", Persona: interfaces.PersonaAuthor, Repo: repo, Branch: "feature/x",
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "egress-check") || !strings.Contains(err.Error(), "destroy-sandbox after") {
		t.Errorf("abort must surface both the cause and the teardown failure, got: %v", err)
	}
}

// stubEngineCloud wraps a MemCloud but overrides RunTask to return a fixed EngineResult, so a test
// can drive the no-change path and assert the signed digest/head/files flow from the engine's
// result rather than a synthesised stand-in. Provision/egress/destroy still go through MemCloud.
type stubEngineCloud struct {
	*devkit.MemCloud
	result interfaces.EngineResult
}

func (c stubEngineCloud) RunTask(context.Context, interfaces.SandboxHandle, interfaces.EngineTask) (interfaces.EngineResult, error) {
	return c.result, nil
}

// TestRun_NoChangeProducesNoPR: when the engine proposes no change (EngineResult.Changed=false), the
// session records a no-change event and ends cleanly — it signs no digest and opens no PR.
func TestRun_NoChangeProducesNoPR(t *testing.T) {
	b := newBench(t)
	b.orch.Cloud = stubEngineCloud{MemCloud: b.cloud, result: interfaces.EngineResult{Changed: false}}
	sum, err := b.orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn: b.authn(t, "alice"), SessionID: "sess-nochange", Persona: interfaces.PersonaAuthor,
		Repo: b.repo, Branch: "feature/x", Attended: false,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if b.scm.OpenPRCount() != 0 {
		t.Error("a no-change session opened a PR")
	}
	if len(sum.CommitDigest) != 0 || sum.HeadSHA != "" {
		t.Errorf("a no-change session signed/recorded a commit: digest=%x head=%q", sum.CommitDigest, sum.HeadSHA)
	}
	var sawNoChange, sawCommit bool
	for i := 0; i < b.evidence.Len(); i++ {
		rec, _, _ := b.evidence.At(i)
		switch rec.Type {
		case "no-change":
			sawNoChange = true
		case "commit-signed", "pr-opened":
			sawCommit = true
		}
	}
	if !sawNoChange {
		t.Error("expected a no-change evidence record")
	}
	if sawCommit {
		t.Error("a no-change session emitted a commit/PR evidence record")
	}
}

// TestRun_SignsEngineProducedCommit: the signed commit attests the engine's REAL output — the head
// SHA and file summary flow from the EngineResult, and the signature verifies over the digest the
// orchestrator derived from it (not a coordinate hash).
func TestRun_SignsEngineProducedCommit(t *testing.T) {
	b := newBench(t)
	want := interfaces.EngineResult{
		CommitDigest: []byte("engine-produced-commit-digest"),
		HeadSHA:      "abc123def456",
		FilesChanged: []string{"main.go", "README.md"},
		Changed:      true,
	}
	b.orch.Cloud = stubEngineCloud{MemCloud: b.cloud, result: want}
	sum, err := b.orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn: b.authn(t, "alice"), SessionID: "sess-engine", Persona: interfaces.PersonaAuthor,
		Repo: b.repo, Branch: "feature/x", Attended: false,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.HeadSHA != want.HeadSHA {
		t.Errorf("HeadSHA = %q, want %q (must flow from the engine result)", sum.HeadSHA, want.HeadSHA)
	}
	if len(sum.FilesChanged) != 2 || sum.FilesChanged[0] != "main.go" {
		t.Errorf("FilesChanged = %v, want it to flow from the engine result", sum.FilesChanged)
	}
	// The signature verifies over the digest the orchestrator signed (derived from the engine digest).
	if err := signing.Verify(b.caRoot, sum.CommitDigest, sum.CommitSig); err != nil {
		t.Errorf("commit signature does not verify: %v", err)
	}
	if len(sum.CommitDigest) == 0 {
		t.Error("expected a non-empty signed commit digest for a changed run")
	}
}

// TestRun_StreamsEachEvidenceRecord: every WORM record is also forwarded to the SIEM hook.
func TestRun_StreamsEachEvidenceRecord(t *testing.T) {
	b := newBench(t)
	sink := &countingSink{MemEvidence: devkit.NewMemEvidence()}
	// Rewire the orchestrator's evidence to the counting sink (same seams otherwise).
	b.orch.Evidence = sink

	if _, err := b.orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn: b.authn(t, "alice"), SessionID: "sess-stream", Persona: interfaces.PersonaAuthor,
		Repo: b.repo, Branch: "feature/x", Attended: false,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sink.streams == 0 || sink.streams != sink.Len() {
		t.Errorf("expected every appended record (%d) to be streamed, got %d streams", sink.Len(), sink.streams)
	}
}
