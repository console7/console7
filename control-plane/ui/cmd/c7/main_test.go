//go:build !c7_live

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/console7/console7/control-plane/ui"
)

// TestWireDevSpine_DrivesAFullSession proves the c7 dev wiring (wireSpine in wire_dev.go) actually
// drives a complete governed session through the orchestrator: a signed proposed commit, a PR (the
// only sanctioned exit), and a WORM evidence chain that genuinely verifies. It is tagged !c7_live —
// the production wireSpine (wire_production.go) needs a real tenancy and is exercised by the operator
// live run, not a unit test.
func TestWireDevSpine_DrivesAFullSession(t *testing.T) {
	repo, err := ui.ParseRepo("acme/widgets")
	if err != nil {
		t.Fatal(err)
	}
	orch, authn, sink, err := wireSpine(repo, "tester@console7.dev")
	if err != nil {
		t.Fatalf("wireSpine: %v", err)
	}
	var out strings.Builder
	spec := ui.LaunchSpec{SessionID: "t1", Repo: "acme/widgets", Branch: "c7/t", Prompt: "fix the typo"}
	if err := ui.Launch(context.Background(), orch, authn, spec, sink, &out); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"PROPOSED commit ",
		"PR: https://github.com/acme/widgets/pull/",
		"evidence chain + lineage VERIFIED",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("session output missing %q\n---\n%s", want, got)
		}
	}
	// The chain the CLI reported VERIFIED must really verify.
	if err := sink.VerifyChain(); err != nil {
		t.Errorf("evidence chain should verify: %v", err)
	}
}
