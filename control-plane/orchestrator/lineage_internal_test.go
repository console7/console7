package orchestrator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
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
	tbs := payloadTBS(0, "alice", "s1", interfaces.PersonaOperate, nhi, "commit-signed", "x")
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
	if err := VerifyRecordPayload(ca.Root(), 0, rec); err == nil {
		t.Error("verified an evidence record whose persona does not match its certified NHI")
	}

	// Sanity: an author record with the matching persona still verifies.
	tbsOK := payloadTBS(0, "alice", "s1", interfaces.PersonaAuthor, nhi, "commit-signed", "x")
	sigOK, _ := b.SignSession(ctx, "s1", tbsOK)
	payloadOK, _ := json.Marshal(stampedPayload{Event: "commit-signed", Detail: "x", Sig: sigOK})
	recOK := interfaces.EvidenceRecord{
		SessionID: "s1", Subject: "alice", Persona: interfaces.PersonaAuthor,
		Type: "commit-signed", Payload: payloadOK,
	}
	if err := VerifyRecordPayload(ca.Root(), 0, recOK); err != nil {
		t.Errorf("a matching-persona record should verify: %v", err)
	}
}

// TestMdInlineCode pins the PR-body sanitiser: an engine-sourced (untrusted) string is rendered as an
// inline-code span that cannot break out — so a crafted filename can render no live link (explicit
// markup OR GFM bare-URL/www/email autolink), and cannot inject an extra body line.
func TestMdInlineCode(t *testing.T) {
	// plain content round-trips inside a single-backtick fence.
	if got := mdInlineCode("normal-dir/file.go"); got != "`normal-dir/file.go`" {
		t.Errorf("plain: got %q, want %q", got, "`normal-dir/file.go`")
	}
	// the inputs the change must neutralise — incl. AUTOLINK triggers (no markup needed on GitHub).
	for _, in := range []string{
		"[Approve](https://evil)", "http://phish.evil/rotate", "www.evil.com/x", "ops@evil.com",
		"a*b_c", "<img src=x>", "row|cell", "x\r\ny z",
	} {
		got := mdInlineCode(in)
		if strings.ContainsAny(got, "\r\n\u0085\u2028\u2029") {
			t.Errorf("mdInlineCode(%q) = %q retains a line/para separator", in, got)
		}
		if !strings.HasPrefix(got, "`") || !strings.HasSuffix(got, "`") {
			t.Errorf("mdInlineCode(%q) = %q is not wrapped as inline code", in, got)
		}
	}
	// embedded backtick runs force a longer fence so content cannot escape the span.
	if got := mdInlineCode("a``b"); !strings.HasPrefix(got, "```") || !strings.HasSuffix(got, "```") {
		t.Errorf("backtick content must use a longer fence, got %q", got)
	}
}

// TestVerifyRecordPayload_RejectsReplayAtDifferentSequence proves the per-record signature now binds
// the CHAIN POSITION (#31): a legitimately signed record verifies at its own sequence but FAILS when
// replayed whole onto a different slot — so a workload-SA/GCS-write holder cannot move a signed record
// to another position even by recomputing the chain hash.
func TestVerifyRecordPayload_RejectsReplayAtDifferentSequence(t *testing.T) {
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

	const nhi = "nhi/s1/author"
	const seq = uint64(3)
	tbs := payloadTBS(seq, "alice", "s1", interfaces.PersonaAuthor, nhi, "tool-call", "ls")
	sig, err := b.SignSession(ctx, "s1", tbs)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	payload, err := json.Marshal(stampedPayload{Event: "tool-call", Detail: "ls", Sig: sig})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := interfaces.EvidenceRecord{
		SessionID: "s1", Subject: "alice", Persona: interfaces.PersonaAuthor, Type: "tool-call", Payload: payload,
	}
	if err := VerifyRecordPayload(ca.Root(), seq, rec); err != nil {
		t.Fatalf("record must verify at its own sequence: %v", err)
	}
	if err := VerifyRecordPayload(ca.Root(), seq+1, rec); err == nil {
		t.Error("a record replayed at a DIFFERENT sequence must fail per-record verification")
	}
}

// misSeqSink lies about NextSequence so appendSigned signs for a slot the record will NOT land in.
type misSeqSink struct{ *devkit.MemEvidence }

func (m misSeqSink) NextSequence(ctx context.Context) (uint64, error) {
	n, err := m.MemEvidence.NextSequence(ctx)
	return n + 7, err
}

// TestAppendSigned_RejectsMisPositionedSequence proves the fail-closed backstop: if the predicted
// sequence does not equal the slot Append assigns, appendSigned errors rather than durably committing
// a record whose lineage signature is bound to the wrong position.
func TestAppendSigned_RejectsMisPositionedSequence(t *testing.T) {
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
	o := &Orchestrator{Broker: b, Evidence: misSeqSink{devkit.NewMemEvidence()}}
	err = o.appendSigned(ctx, "s1", "alice", interfaces.PersonaAuthor, "nhi/s1/author", "tool-call", "ls")
	if err == nil || !strings.Contains(err.Error(), "raced") {
		t.Errorf("expected a fail-closed sequence-mismatch error, got: %v", err)
	}
}
