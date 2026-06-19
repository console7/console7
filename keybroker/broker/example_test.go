package broker_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

// ExampleBroker_MintSessionIdentity is runnable documentation of the Phase-0 flow: a
// verified login yields a per-session non-human identity that signs an action whose
// lineage traces back to the human. Output is deterministic (no secrets or random refs
// are printed).
func ExampleBroker_MintSessionIdentity() {
	// Wire the in-memory dev seams (a bench, not a deployment).
	reg := devkit.NewSandboxRegistry()
	ca := signing.NewDevCA()
	idpPub, idpPriv, _ := ed25519.GenerateKey(nil)
	b := broker.New(
		devkit.NewDevIdentity(idpPub, nil),
		devkit.NewMemSecrets(reg),
		devkit.NewMemSCM(15*time.Minute),
		devkit.NewPolicyInference(devkit.SeamPolicy{SubscriptionEnabled: true}),
		signing.NewNHIBinder(ca),
	)

	// A verified SSO assertion -> a credentialed session.
	authn := devkit.IssueDevAssertion(idpPriv, "alice", time.Now().Add(time.Hour))
	minted, err := b.MintSessionIdentity(context.Background(), broker.SessionRequest{
		Authn:           authn,
		SessionID:       "s1",
		Persona:         interfaces.PersonaAuthor,
		Repo:            interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:          "feature/x",
		Scopes:          []string{"repo:read"},
		TTL:             time.Hour,
		SessionDeadline: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// The NHI signs a commit via the broker (its key never leaves it); the lineage verifies
	// back to the human subject.
	digest := []byte("sha256:commit")
	sig, _ := b.SignSession(context.Background(), "s1", digest)
	verified := signing.Verify(ca.Root(), digest, sig) == nil

	fmt.Println("subject:", minted.Identity.Subject)
	fmt.Println("nhi:", minted.NHI)
	fmt.Println("lineage verified:", verified)
	// Output:
	// subject: alice
	// nhi: nhi/s1/author
	// lineage verified: true
}
