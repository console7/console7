package main

import (
	"context"
	"strings"
	"testing"

	"github.com/console7/console7/control-plane/ui"
)

// TestWireDevSpine_DrivesAFullSession proves the c7 dev wiring actually drives a complete governed
// session through the orchestrator: a signed proposed commit, a PR (the only sanctioned exit), and a
// WORM evidence chain that genuinely verifies — the live-cluster equivalent is the operator-run B11.
func TestWireDevSpine_DrivesAFullSession(t *testing.T) {
	repo, err := ui.ParseRepo("acme/widgets")
	if err != nil {
		t.Fatal(err)
	}
	orch, authn, sink, err := wireDevSpine(repo, "tester@console7.dev")
	if err != nil {
		t.Fatalf("wireDevSpine: %v", err)
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
		"evidence chain VERIFIED",
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
