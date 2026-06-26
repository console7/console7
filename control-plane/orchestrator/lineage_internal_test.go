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
