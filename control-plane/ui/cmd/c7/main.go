// Command c7 is the thin Console7 CLI: launch one governed session, watch its lifecycle, and review
// the proposed PR + evidence verdict. It is a thin client of the orchestrator (control-plane/ui).
//
// THIS BINARY WIRES A NON-PRODUCTION DEV SPINE (the in-memory devkit seams) so `c7 launch` runs a
// full session locally for demonstration and CI. The PRODUCTION wiring — the real GCP/GitHub/Anthropic
// seams + an SSO-obtained authn token instead of a dev assertion — is the operator/B11 path; the
// orchestrator surface c7 drives (ui.Launch) is identical for both.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/control-plane/orchestrator"
	"github.com/console7/console7/control-plane/ui"
	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
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
	user := fs.String("user", "operator@console7.dev", "subject for the dev SSO assertion")
	attended := fs.Bool("attended", false, "a human is present (enables --subscription)")
	sub := fs.Bool("subscription", false, "use the vaulted subscription token (attended only; the dev spine has no vaulted token — Part A)")
	_ = fs.Parse(os.Args[2:])

	sid := *session
	if sid == "" {
		sid = fmt.Sprintf("c7-%d", time.Now().UnixNano())
	}
	spec := ui.LaunchSpec{
		SessionID: sid, Repo: *repo, Branch: *branch, Prompt: *prompt,
		Persona: *persona, Attended: *attended, UseSubscription: *sub,
	}

	// Resolve the repo up front so the dev PolicySoR can register it — the resolved profile drives the
	// egress allowlist the inference endpoint must be on (the CLI core re-validates it under Launch).
	repoRef, err := ui.ParseRepo(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	orch, authn, sink, err := wireDevSpine(repoRef, *user)
	if err != nil {
		fmt.Fprintln(os.Stderr, "c7: wire dev spine:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "c7: NON-PRODUCTION dev spine (in-memory seams); the live GCP wiring + SSO is the operator/B11 path.")
	if err := ui.Launch(context.Background(), orch, authn, spec, sink, os.Stdout); err != nil {
		os.Exit(1)
	}
}

// devOrgAPIEndpoint / devSubscriptionEndpoint are the dev spine's fixed inference endpoints; both are
// placed on the session's egress allowlist so the resolved endpoint passes the boundary check.
const (
	devOrgAPIEndpoint       = "https://api.anthropic.com"
	devSubscriptionEndpoint = "https://subscription.internal/inference"
)

// wireDevSpine assembles the NON-PRODUCTION in-memory orchestrator spine (the same devkit seams the
// orchestrator bench uses) and a dev SSO assertion for user. It mirrors a real control-plane main:
// real wiring swaps the devkit seams for providers/* and the dev assertion for an SSO token.
func wireDevSpine(repo interfaces.RepoRef, user string) (*orchestrator.Orchestrator, interfaces.AuthnToken, *evidence.Sink, error) {
	reg := devkit.NewSandboxRegistry()
	cloud := devkit.NewMemCloud(reg)
	secrets := devkit.NewMemSecrets(reg)
	// The adopter's shared org API credential (org-API lane); configured out-of-band, never carried
	// through the seam (B9b). A real deployment loads it into the SecretsProvider's secrets manager.
	if err := secrets.SetOrgCredential([]byte("DEV-PLACEHOLDER-not-a-real-key")); err != nil {
		return nil, "", nil, err
	}
	ca := signing.NewDevCA()
	binder := signing.NewNHIBinder(ca)
	idpPub, idpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, "", nil, err
	}
	idp := devkit.NewDevIdentity(idpPub, nil)
	inference := devkit.NewPolicyInference(devkit.SeamPolicy{
		SubscriptionEndpoint: devSubscriptionEndpoint,
		OrgAPIEndpoint:       devOrgAPIEndpoint,
		SubscriptionEnabled:  true,
	})
	b := broker.New(idp, secrets, devkit.NewMemSCM(15*time.Minute), inference, binder)

	sinkSigner, err := signing.NewSinkSigner(ca, "c7-dev-evidence-sink")
	if err != nil {
		return nil, "", nil, err
	}
	sink := evidence.NewInMemory(sinkSigner, ca.Root(), 0)
	orch := orchestrator.New(b, cloud, sink, devkit.NewFixedPolicySoR(repo),
		[]string{devOrgAPIEndpoint, devSubscriptionEndpoint}, 30*time.Minute)
	authn := devkit.IssueDevAssertion(idpPriv, interfaces.Subject(user), time.Now().Add(time.Hour))
	return orch, authn, sink, nil
}
