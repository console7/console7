package ui

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"

	"github.com/console7/console7/control-plane/orchestrator"
	"github.com/console7/console7/sdk/interfaces"
)

type lineageFn = func(caRoot crypto.PublicKey, seq uint64, rec interfaces.EvidenceRecord) error

type fakeRunner struct {
	sum orchestrator.Summary
	err error
	got orchestrator.LaunchRequest
}

func (f *fakeRunner) Run(_ context.Context, req orchestrator.LaunchRequest) (orchestrator.Summary, error) {
	f.got = req
	return f.sum, f.err
}

type okVerifier struct{}

func (okVerifier) VerifyChain() error            { return nil }
func (okVerifier) VerifyLineage(lineageFn) error { return nil }

type badVerifier struct{}

func (badVerifier) VerifyChain() error            { return errors.New("hash mismatch at record 3") }
func (badVerifier) VerifyLineage(lineageFn) error { return nil }

// badLineageVerifier passes the hash chain but fails per-record lineage verification.
type badLineageVerifier struct{}

func (badLineageVerifier) VerifyChain() error { return nil }
func (badLineageVerifier) VerifyLineage(lineageFn) error {
	return errors.New("record 2 lineage signature invalid")
}

func TestLaunchSpec_toRequest(t *testing.T) {
	// owner/name defaults the host; persona defaults to author; subscription is attended-gated.
	req, err := LaunchSpec{SessionID: "s1", Repo: "acme/widgets", Branch: "c7/x", Prompt: "fix it", UseSubscription: true}.toRequest("tok")
	if err != nil {
		t.Fatalf("valid spec: %v", err)
	}
	if req.Repo != (interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "widgets"}) {
		t.Errorf("repo = %+v", req.Repo)
	}
	if req.Persona != interfaces.PersonaAuthor || req.Authn != "tok" || req.SessionID != "s1" {
		t.Errorf("request fields wrong: %+v", req)
	}
	if req.UseSubscription {
		t.Error("subscription must be gated off when the session is unattended (tenet 2)")
	}

	// host/owner/name is honoured; operate persona parses; attended+subscription survives.
	req2, err := LaunchSpec{SessionID: "s2", Repo: "git.acme.io/team/svc", Branch: "c7/y", Prompt: "p", Persona: "operate", Attended: true, UseSubscription: true}.toRequest("t")
	if err != nil {
		t.Fatalf("3-part repo: %v", err)
	}
	if req2.Repo.Host != "git.acme.io" || req2.Persona != interfaces.PersonaOperate || !req2.UseSubscription {
		t.Errorf("request2 fields wrong: %+v", req2)
	}

	for _, tc := range []struct {
		name string
		spec LaunchSpec
	}{
		{"bad repo", LaunchSpec{SessionID: "s", Repo: "widgets", Branch: "b", Prompt: "p"}},
		{"empty repo part", LaunchSpec{SessionID: "s", Repo: "acme/", Branch: "b", Prompt: "p"}},
		{"missing session", LaunchSpec{Repo: "a/b", Branch: "b", Prompt: "p"}},
		{"missing branch", LaunchSpec{SessionID: "s", Repo: "a/b", Prompt: "p"}},
		{"missing prompt", LaunchSpec{SessionID: "s", Repo: "a/b", Branch: "b"}},
		{"bad persona", LaunchSpec{SessionID: "s", Repo: "a/b", Branch: "b", Prompt: "p", Persona: "root"}},
	} {
		if _, err := tc.spec.toRequest("tok"); err == nil {
			t.Errorf("%s: expected a validation error", tc.name)
		}
	}
}

func TestLaunch_RendersProposalAndVerifiedEvidence(t *testing.T) {
	r := &fakeRunner{sum: orchestrator.Summary{
		NHI:          "nhi/s1/author",
		Inference:    interfaces.BackendEndpoint{URL: "https://api.anthropic.com", Kind: interfaces.BackendAnthropicAPI},
		HeadSHA:      "abc1234deadbeef",
		FilesChanged: []string{"README.md"},
		PR:           interfaces.PRRef{URL: "https://github.com/acme/widgets/pull/7", Number: 7},
		Records:      7,
	}}
	var out strings.Builder
	spec := LaunchSpec{SessionID: "s1", Repo: "acme/widgets", Branch: "c7/x", Prompt: "fix the typo"}
	if err := Launch(context.Background(), r, "tok", spec, okVerifier{}, &out); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"session s1: launching (org-API lane, branch c7/x)...",
		"inference resolved -> https://api.anthropic.com",
		"PROPOSED commit abc1234 (1 file) signed by NHI nhi/s1/author",
		"PR: https://github.com/acme/widgets/pull/7",
		"evidence chain + lineage VERIFIED (7 records)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n---\n%s", want, got)
		}
	}
	// The request actually carried the parsed prompt/branch to the orchestrator.
	if r.got.Prompt != "fix the typo" || r.got.Branch != "c7/x" {
		t.Errorf("orchestrator got wrong request: %+v", r.got)
	}
}

func TestLaunch_NoChangeAndTamperAndError(t *testing.T) {
	// No-change session: clean tree, no PROPOSED line; nil verifier ⇒ records-sealed (no verdict).
	var out1 strings.Builder
	r1 := &fakeRunner{sum: orchestrator.Summary{Records: 3, Inference: interfaces.BackendEndpoint{URL: "u", Kind: interfaces.BackendAnthropicAPI}}}
	_ = Launch(context.Background(), r1, "t", LaunchSpec{SessionID: "s", Repo: "a/b", Branch: "x", Prompt: "p"}, nil, &out1)
	if !strings.Contains(out1.String(), "no change proposed") || !strings.Contains(out1.String(), "3 records sealed") {
		t.Errorf("no-change/nil-verifier output wrong:\n%s", out1.String())
	}

	// Tampered evidence ⇒ INVALID verdict.
	var out2 strings.Builder
	r2 := &fakeRunner{sum: orchestrator.Summary{HeadSHA: "deadbeef", FilesChanged: []string{"a", "b"}, Records: 4}}
	_ = Launch(context.Background(), r2, "t", LaunchSpec{SessionID: "s", Repo: "a/b", Branch: "x", Prompt: "p"}, badVerifier{}, &out2)
	if !strings.Contains(out2.String(), "evidence chain INVALID") || !strings.Contains(out2.String(), "2 files") {
		t.Errorf("tamper output wrong:\n%s", out2.String())
	}

	// Run error ⇒ FAILED line + non-nil return.
	var out3 strings.Builder
	r3 := &fakeRunner{err: errors.New("provision failed")}
	err := Launch(context.Background(), r3, "t", LaunchSpec{SessionID: "s", Repo: "a/b", Branch: "x", Prompt: "p"}, okVerifier{}, &out3)
	if err == nil || !strings.Contains(out3.String(), "FAILED: provision failed") {
		t.Errorf("error path wrong: err=%v out=%s", err, out3.String())
	}

	// Validation error ⇒ surfaced to the writer (not silently swallowed) + non-nil return.
	var out4 strings.Builder
	err4 := Launch(context.Background(), &fakeRunner{}, "t", LaunchSpec{SessionID: "s", Repo: "a/b", Prompt: "p"}, nil, &out4) // missing branch
	if err4 == nil || !strings.Contains(out4.String(), "branch is required") {
		t.Errorf("validation error not surfaced: err=%v out=%q", err4, out4.String())
	}
}

// TestLaunch_LineageInvalidVerdict: a chain that hash-verifies but whose per-record lineage signature
// fails must render LINEAGE INVALID, never a clean VERIFIED verdict.
func TestLaunch_LineageInvalidVerdict(t *testing.T) {
	r := &fakeRunner{sum: orchestrator.Summary{Records: 4, HeadSHA: "abcdef0", FilesChanged: []string{"x"}}}
	var out strings.Builder
	_ = Launch(context.Background(), r, "t", LaunchSpec{SessionID: "s", Repo: "a/b", Branch: "x", Prompt: "p"}, badLineageVerifier{}, &out)
	if !strings.Contains(out.String(), "evidence LINEAGE INVALID") {
		t.Errorf("expected LINEAGE INVALID verdict, got: %s", out.String())
	}
	if strings.Contains(out.String(), "VERIFIED") {
		t.Errorf("must not report VERIFIED when lineage fails, got: %s", out.String())
	}
}
