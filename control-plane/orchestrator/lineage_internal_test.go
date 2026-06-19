package orchestrator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

// TestVerifyRecordPayload_RejectsPersonaNotMatchingNHI proves the evidence persona is bound
// to the persona CERTIFIED into the NHI, not merely present in the signed bytes. It is a
// white-box test (package orchestrator) because it forges a record the way a holder of the
// signing oracle would: it asks an AUTHOR session to sign an evidence TBS that claims
// PersonaOperate. The signature is valid over those bytes, but the NHI certifies "author",
// so verification must reject the cross-persona attribution.
func TestVerifyRecordPayload_RejectsPersonaNotMatchingNHI(t *testing.T) {
	reg := devkit.NewSandboxRegistry()
	ca := signing.NewDevCA()
	idpPub, idpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	b := broker.New(devkit.NewDevIdentity(idpPub, nil), devkit.NewMemSecrets(reg),
		devkit.NewMemSCM(15*time.Minute), devkit.NewPolicyInference(devkit.SeamPolicy{}),
		signing.NewNHIBinder(ca))
	ctx := context.Background()
	if _, err := b.MintSessionIdentity(ctx, broker.SessionRequest{
		Authn:           devkit.IssueDevAssertion(idpPriv, "alice", time.Now().Add(time.Hour)),
		SessionID:       "s1",
		Persona:         interfaces.PersonaAuthor,
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		TTL:             time.Hour,
		SessionDeadline: time.Now().Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Forge: the author session signs an evidence TBS that CLAIMS persona "operate".
	const nhi = "nhi/s1/author"
	tbs := payloadTBS("alice", "s1", interfaces.PersonaOperate, nhi, "commit-signed", "x")
	sig, err := b.SignSession(ctx, "s1", tbs)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	payload, err := json.Marshal(stampedPayload{Event: "commit-signed", Detail: "x", Sig: sig})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := interfaces.EvidenceRecord{
		SessionID: "s1", Subject: "alice", Persona: interfaces.PersonaOperate,
		Type: "commit-signed", Payload: payload,
	}
	if err := VerifyRecordPayload(ca.Root(), rec); err == nil {
		t.Error("verified an evidence record whose persona does not match its certified NHI")
	}

	// Sanity: an author record with the matching persona still verifies.
	tbsOK := payloadTBS("alice", "s1", interfaces.PersonaAuthor, nhi, "commit-signed", "x")
	sigOK, _ := b.SignSession(ctx, "s1", tbsOK)
	payloadOK, _ := json.Marshal(stampedPayload{Event: "commit-signed", Detail: "x", Sig: sigOK})
	recOK := interfaces.EvidenceRecord{
		SessionID: "s1", Subject: "alice", Persona: interfaces.PersonaAuthor,
		Type: "commit-signed", Payload: payloadOK,
	}
	if err := VerifyRecordPayload(ca.Root(), recOK); err != nil {
		t.Errorf("a matching-persona record should verify: %v", err)
	}
}
