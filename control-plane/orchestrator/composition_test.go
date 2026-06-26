package orchestrator_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/control-plane/orchestrator"
	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	evidencegcs "github.com/console7/console7/providers/evidence-gcs"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

// TestComposition_SigningLineageWORM_OverEvidenceGCSStore is the hermetic headline proof for the
// Phase-1 EXIT signing/lineage/WORM closure: it drives a FULL orchestrator.Run against the REAL
// control-plane/evidence.Sink committing through the REAL providers/evidence-gcs Store code path
// (NewWithObjectIO over the in-memory objectIO fake — the GCS encode/append/At/Len/preflight logic,
// not evidence.NewInMemory's bench store), with real keybroker signing. It asserts the orchestrated
// flow produces a signed commit, per-record SSO->NHI lineage, and a sealed, verifiable WORM chain —
// repeatably, with no cloud. The live operator run only has to confirm this survives real GCS/KMS;
// the closure itself is proven here. (The bench's TestSpike uses the in-memory store; this is the
// missing wiring: orchestrator -> evidence.Sink -> evidence-gcs Store, end to end.)
func TestComposition_SigningLineageWORM_OverEvidenceGCSStore(t *testing.T) {
	reg := devkit.NewSandboxRegistry()
	cloud := devkit.NewMemCloud(reg)
	secrets := devkit.NewMemSecrets(reg)
	if err := secrets.SetOrgCredential([]byte("composition-org-api-key")); err != nil {
		t.Fatalf("SetOrgCredential: %v", err)
	}
	ca := signing.NewDevCA()
	binder := signing.NewNHIBinder(ca)
	idpPub, idpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("idp keygen: %v", err)
	}
	idp := devkit.NewDevIdentity(idpPub, nil)
	inference := devkit.NewPolicyInference(devkit.SeamPolicy{OrgAPIEndpoint: orgAPIURL, SubscriptionEnabled: false})
	b := broker.New(idp, secrets, devkit.NewMemSCM(15*time.Minute), inference, binder)

	sinkSigner, err := signing.NewSinkSigner(ca, "composition-evidence-sink")
	if err != nil {
		t.Fatalf("NewSinkSigner: %v", err)
	}
	// THE POINT: the evidence sink commits through the REAL evidence-gcs Store (its GCS object
	// encode/append/no-gap/preflight code), wired over the in-memory objectIO fake — not the bench's
	// in-memory store. ckptEvery=0 seals one checkpoint at session-end.
	store := evidencegcs.NewWithObjectIO(evidencegcs.NewInMemoryObjectIO(), "records")
	sink := evidence.New(store, sinkSigner, ca.Root(), 0)

	repo := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	orch := orchestrator.New(b, cloud, sink, devkit.NewFixedPolicySoR(repo), []string{orgAPIURL}, 30*time.Minute)

	authn := devkit.IssueDevAssertion(idpPriv, "alice", time.Now().Add(time.Hour))
	sum, err := orch.Run(context.Background(), orchestrator.LaunchRequest{
		Authn:     authn,
		SessionID: "comp-1",
		Persona:   interfaces.PersonaAuthor,
		Repo:      repo,
		Branch:    "feature/comp",
		Attended:  false, // org-API lane
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// (1) A real, signed proposed commit.
	if sum.HeadSHA == "" || len(sum.CommitDigest) == 0 {
		t.Fatalf("expected a signed proposed commit, got HeadSHA=%q digest=%d bytes", sum.HeadSHA, len(sum.CommitDigest))
	}
	if err := signing.Verify(ca.Root(), sum.CommitDigest, sum.CommitSig); err != nil {
		t.Errorf("commit signature does not verify: %v", err)
	}
	if sum.CommitSig.Subject != "alice" {
		t.Errorf("commit signature subject = %q, want alice", sum.CommitSig.Subject)
	}

	// (2) WORM: the chain committed THROUGH the evidence-gcs Store is unbroken, sink-sealed, and
	// fully covers the head — the single auditor call over the real store path.
	if err := sink.Verify(); err != nil {
		t.Errorf("evidence WORM verify (over the evidence-gcs Store) failed: %v", err)
	}
	if len(sink.Checkpoints()) == 0 {
		t.Error("expected at least one sink-signed checkpoint sealing the session")
	}

	// (3) Per-record SSO->NHI lineage verifies for every record, in the expected order.
	wantEvents := []string{
		"session-start", "sandbox-provisioned", "inference-resolved", "egress-narrowed",
		"org-credential-injected", "repo-seeded", "commit-signed", "branch-pushing", "branch-pushed",
		"pr-opening", "pr-opened", "session-end",
	}
	if sink.Len() != len(wantEvents) {
		t.Fatalf("evidence has %d records, want %d", sink.Len(), len(wantEvents))
	}
	for i, want := range wantEvents {
		rec, _, ok := sink.At(i)
		if !ok {
			t.Fatalf("missing record %d", i)
		}
		if rec.Type != want {
			t.Errorf("record %d type = %q, want %q", i, rec.Type, want)
		}
		if err := orchestrator.VerifyRecordPayload(ca.Root(), uint64(i), rec); err != nil {
			t.Errorf("record %d (%s) lineage does not verify: %v", i, rec.Type, err)
		}
	}

	// (4) Tamper case: the per-record lineage signature binds the record's OWN attribution — altering
	// the Subject an auditor reads off a record breaks verification.
	rec, _, ok := sink.At(0)
	if !ok {
		t.Fatal("missing record 0 for tamper check")
	}
	rec.Subject = "mallory"
	if err := orchestrator.VerifyRecordPayload(ca.Root(), 0, rec); err == nil {
		t.Error("a tampered record Subject should fail lineage verification")
	}
}
