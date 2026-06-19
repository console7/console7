package devkit

import (
	"context"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

func newMemCloud() (*MemCloud, *SandboxRegistry) {
	reg := NewSandboxRegistry()
	return NewMemCloud(reg), reg
}

func provisionSpec(session interfaces.SessionID, allow ...string) interfaces.SandboxSpec {
	return interfaces.SandboxSpec{
		SessionID: session,
		Subject:   interfaces.Subject("alice"),
		Persona:   interfaces.PersonaAuthor,
		Egress:    interfaces.EgressPolicy{Allowlist: allow},
		MaxTTL:    time.Minute,
	}
}

func TestMemCloud_ProvisionSandbox_RejectsNonPositiveTTL(t *testing.T) {
	cloud, _ := newMemCloud()
	spec := provisionSpec("s1", "https://a")
	spec.MaxTTL = 0
	if _, err := cloud.ProvisionSandbox(context.Background(), spec); err == nil {
		t.Fatal("expected provision to reject a non-positive MaxTTL (ephemeral by default)")
	}
}

func TestMemCloud_ProvisionSandbox_RegistersOwnershipAndIsUnique(t *testing.T) {
	cloud, reg := newMemCloud()
	ctx := context.Background()

	h1, err := cloud.ProvisionSandbox(ctx, provisionSpec("s1", "https://a"))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	h2, err := cloud.ProvisionSandbox(ctx, provisionSpec("s2", "https://a"))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if h1.ID == h2.ID || h1.ID == "" {
		t.Fatalf("expected two distinct non-empty handles, got %q and %q", h1.ID, h2.ID)
	}
	// The registry the SecretsProvider checks must already know the provisioned sandbox's
	// owner — that is how a subscription injection can verify it reaches the right sandbox.
	if !reg.Owns(h1, "alice", "s1") {
		t.Error("registry does not record ownership of the provisioned sandbox")
	}
	if reg.Owns(h1, "alice", "s2") {
		t.Error("registry confused ownership across sessions")
	}
}

func TestMemCloud_ApplyEgressPolicy_NarrowOnly(t *testing.T) {
	cloud, _ := newMemCloud()
	ctx := context.Background()
	h, err := cloud.ProvisionSandbox(ctx, provisionSpec("s1", "https://a", "https://b"))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Narrowing (a subset) is permitted.
	if err := cloud.ApplyEgressPolicy(ctx, h, interfaces.EgressPolicy{Allowlist: []string{"https://a"}}); err != nil {
		t.Fatalf("narrowing should be permitted: %v", err)
	}
	if got, _ := cloud.EgressOf(h); len(got) != 1 || got[0] != "https://a" {
		t.Fatalf("egress not narrowed, got %v", got)
	}
	// Widening — re-adding a now-removed destination — must be refused (fail closed).
	if err := cloud.ApplyEgressPolicy(ctx, h, interfaces.EgressPolicy{Allowlist: []string{"https://a", "https://b"}}); err == nil {
		t.Error("expected widening egress beyond the current allowlist to be refused")
	}
}

func TestMemCloud_ApplyEgressPolicy_UnknownSandboxFailsClosed(t *testing.T) {
	cloud, _ := newMemCloud()
	if err := cloud.ApplyEgressPolicy(context.Background(), interfaces.SandboxHandle{ID: "nope"}, interfaces.EgressPolicy{Allowlist: []string{"https://a"}}); err == nil {
		t.Error("expected applying egress to an unknown sandbox to fail closed")
	}
}

func TestMemCloud_DestroySandbox_IrreversibleAndWipes(t *testing.T) {
	cloud, reg := newMemCloud()
	ctx := context.Background()
	h, err := cloud.ProvisionSandbox(ctx, provisionSpec("s1", "https://a"))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Land some injected material via the SecretsProvider so we can prove destroy wipes it.
	secrets := NewMemSecrets(reg)
	if err := secrets.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: "alice", Token: []byte("tok")}); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := secrets.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: "alice", SessionID: "s1", Sandbox: h, Attended: true, Beneficiaries: 1,
	}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if _, ok := reg.Injected(h); !ok {
		t.Fatal("precondition: expected injected material before destroy")
	}

	if err := cloud.DestroySandbox(ctx, h); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if cloud.Live(h) {
		t.Error("sandbox still live after destroy")
	}
	if _, ok := reg.Injected(h); ok {
		t.Error("destroy did not wipe injected credential material")
	}
	if reg.Owns(h, "alice", "s1") {
		t.Error("destroy did not remove the ownership binding")
	}
	// Irreversible: a second destroy fails closed; no operation resurrects it.
	if err := cloud.DestroySandbox(ctx, h); err == nil {
		t.Error("expected a second destroy to fail closed")
	}
}
