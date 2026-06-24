// Command c7 is the thin Console7 CLI: launch one governed session, watch its lifecycle, and review
// the proposed PR + evidence verdict. It is a thin client of the orchestrator (control-plane/ui).
//
// The orchestrator spine c7 drives (ui.Launch) is IDENTICAL in dev and production — only the WIRING
// differs, selected at BUILD time:
//   - default build  (wire_dev.go,  //go:build !c7_live): the NON-PRODUCTION in-memory devkit seams,
//     so `c7 launch` runs a full session locally for demonstration and CI.
//   - `-tags c7_live` (wire_production.go): the REAL GCP/GitHub/inference seams + the KMS-backed
//     keybroker CA + the GCS WORM evidence sink, configured from the environment — the operator path
//     for the Phase-1 EXIT live run. It is compiled (CI runs `go build -tags c7_live`) but never RUN
//     in CI; it needs a real tenancy.
//
// Both paths supply wireSpine + a spineBanner const; main.go is build-tag-neutral.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/console7/console7/control-plane/ui"
)

const usage = "usage: c7 launch --repo owner/name --branch <b> --prompt <p> [--session-id id] " +
	"[--persona author|operate] [--user subject] [--attended] [--subscription]"

func main() {
	if len(os.Args) < 2 || os.Args[1] != "launch" {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet("launch", flag.ExitOnError)
	repo := fs.String("repo", "", "target repo: owner/name or host/owner/name")
	branch := fs.String("branch", "", "fresh working branch")
	prompt := fs.String("prompt", "", "task instruction for the engine")
	session := fs.String("session-id", "", "session id (default: c7-<timestamp>)")
	persona := fs.String("persona", "author", "author|operate")
	user := fs.String("user", "operator@console7.dev", "subject for the SSO assertion")
	attended := fs.Bool("attended", false, "a human is present (enables --subscription)")
	sub := fs.Bool("subscription", false, "use the vaulted subscription token (attended only)")
	_ = fs.Parse(os.Args[2:])

	sid := *session
	if sid == "" {
		sid = fmt.Sprintf("c7-%d", time.Now().UnixNano())
	}
	spec := ui.LaunchSpec{
		SessionID: sid, Repo: *repo, Branch: *branch, Prompt: *prompt,
		Persona: *persona, Attended: *attended, UseSubscription: *sub,
	}

	// Resolve the repo up front so the PolicySoR can register it — the resolved profile drives the
	// egress allowlist the inference endpoint must be on (the CLI core re-validates it under Launch).
	repoRef, err := ui.ParseRepo(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	orch, authn, sink, err := wireSpine(repoRef, *user)
	if err != nil {
		fmt.Fprintln(os.Stderr, "c7: wire spine:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "c7: "+spineBanner)
	if err := ui.Launch(context.Background(), orch, authn, spec, sink, os.Stdout); err != nil {
		os.Exit(1)
	}
}
