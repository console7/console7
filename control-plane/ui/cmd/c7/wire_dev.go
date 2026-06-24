//go:build !c7_live

package main

import (
	"crypto/ed25519"
	"time"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/control-plane/orchestrator"
	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

// spineBanner is printed at launch so it is never ambiguous which wiring a binary carries.
const spineBanner = "NON-PRODUCTION dev spine (in-memory seams); the live GCP/GitHub wiring + SSO is the -tags c7_live build."

// devOrgAPIEndpoint / devSubscriptionEndpoint are the dev spine's fixed inference endpoints; both are
// placed on the session's egress allowlist so the resolved endpoint passes the boundary check.
const (
	devOrgAPIEndpoint       = "https://api.anthropic.com"
	devSubscriptionEndpoint = "https://subscription.internal/inference"
)

// wireSpine assembles the NON-PRODUCTION in-memory orchestrator spine (the same devkit seams the
// orchestrator bench uses) and a dev SSO assertion for user. The production counterpart
// (wire_production.go, -tags c7_live) swaps the devkit seams for providers/* and returns the SAME
// tuple — the ui.Launch surface main.go drives is identical.
func wireSpine(repo interfaces.RepoRef, user string) (*orchestrator.Orchestrator, interfaces.AuthnToken, *evidence.Sink, error) {
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
