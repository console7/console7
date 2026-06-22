package cloudgcp

import (
	"context"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// injectorShape is the structural seam providers/secrets-gcp.Injector expects. Asserting *Provider
// satisfies it here (without importing secrets-gcp) guarantees the cloud-gcp Provider can be wired
// as the production data-plane Injector — the role secrets-gcp's denyInjector stands in for today.
type injectorShape interface {
	Owns(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID) bool
	DeliverIfOwned(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID, material []byte) bool
}

var _ injectorShape = (*Provider)(nil)

func newProviderWithDeliverer(t *testing.T) (*Provider, *InMemoryCredentialDeliverer) {
	t.Helper()
	p, err := NewWithPorts(NewInMemorySandboxRuntime(), NewInMemoryEgressController(), NewInMemoryEngineRunner(), "console7", nil)
	if err != nil {
		t.Fatalf("NewWithPorts: %v", err)
	}
	dl := NewInMemoryCredentialDeliverer()
	p.SetCredentialDeliverer(dl)
	return p, dl
}

func provisionFor(t *testing.T, p *Provider, subject interfaces.Subject, session interfaces.SessionID) interfaces.SandboxHandle {
	t.Helper()
	h, err := p.ProvisionSandbox(context.Background(), interfaces.SandboxSpec{
		SessionID: session, Subject: subject, Persona: interfaces.PersonaAuthor, MaxTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("ProvisionSandbox: %v", err)
	}
	return h
}

func TestProvider_OwnsAndDeliverIfOwned(t *testing.T) {
	p, dl := newProviderWithDeliverer(t)
	h := provisionFor(t, p, "alice@example.test", "sess-1")

	// The exact owner owns it; a mismatched subject, session, or unknown handle does not (fail closed).
	if !p.Owns(h, "alice@example.test", "sess-1") {
		t.Fatal("the provisioning owner should own the sandbox")
	}
	for _, tc := range []struct {
		name    string
		subject interfaces.Subject
		session interfaces.SessionID
		h       interfaces.SandboxHandle
	}{
		{"wrong subject", "mallory@example.test", "sess-1", h},
		{"wrong session", "alice@example.test", "sess-2", h},
		{"unknown handle", "alice@example.test", "sess-1", interfaces.SandboxHandle{ID: "console7-sb-deadbeef"}},
	} {
		if p.Owns(tc.h, tc.subject, tc.session) {
			t.Errorf("%s: Owns should be false (fail closed)", tc.name)
		}
		if p.DeliverIfOwned(tc.h, tc.subject, tc.session, []byte("k")) {
			t.Errorf("%s: DeliverIfOwned should refuse a non-owner", tc.name)
		}
	}
	if _, delivered := dl.Delivered(h); delivered {
		t.Fatal("no material should have been delivered to a non-owner's sandbox")
	}

	// The owner's delivery lands a copy of the material in the (memory) pod volume.
	if !p.DeliverIfOwned(h, "alice@example.test", "sess-1", []byte("sk-ant-secret")) {
		t.Fatal("DeliverIfOwned should deliver to the owner")
	}
	got, ok := dl.Delivered(h)
	if !ok || string(got) != "sk-ant-secret" {
		t.Fatalf("delivered material = %q, ok=%v; want the owner's material", got, ok)
	}
}

func TestProvider_DeliverFailClosed(t *testing.T) {
	p, dl := newProviderWithDeliverer(t)
	h := provisionFor(t, p, "alice@example.test", "sess-1")
	dl.SetFailDeliver(true)
	if p.DeliverIfOwned(h, "alice@example.test", "sess-1", []byte("k")) {
		t.Fatal("a delivery error must report non-delivery (fail closed)")
	}
}

func TestProvider_NoDelivererWiredIsFailClosed(t *testing.T) {
	// A Provider built via NewWithPorts without SetCredentialDeliverer keeps the deny default.
	p, err := NewWithPorts(NewInMemorySandboxRuntime(), NewInMemoryEgressController(), NewInMemoryEngineRunner(), "console7", nil)
	if err != nil {
		t.Fatalf("NewWithPorts: %v", err)
	}
	h := provisionFor(t, p, "alice@example.test", "sess-1")
	if p.DeliverIfOwned(h, "alice@example.test", "sess-1", []byte("k")) {
		t.Fatal("DeliverIfOwned must refuse when no real deliverer is wired (fail closed)")
	}
}

func TestProvider_DestroyedAndExpiredNotOwned(t *testing.T) {
	p, dl := newProviderWithDeliverer(t)
	h := provisionFor(t, p, "alice@example.test", "sess-1")
	if err := p.DestroySandbox(context.Background(), h); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
	if p.Owns(h, "alice@example.test", "sess-1") {
		t.Error("a destroyed sandbox is not owned")
	}
	if p.DeliverIfOwned(h, "alice@example.test", "sess-1", []byte("k")) {
		t.Error("DeliverIfOwned must refuse a destroyed sandbox")
	}
	if !dl.Wiped(h) {
		t.Error("destroy should best-effort wipe the injected credential")
	}
}

func TestProvider_TaintedNotOwned(t *testing.T) {
	// Taint the sandbox by forcing every egress Set to fail during a widen attempt (the deny-all
	// fallback then also fails, which taints). A sandbox whose perimeter is not guaranteed must not
	// receive a credential.
	rt := NewInMemorySandboxRuntime()
	eg := NewInMemoryEgressController()
	p, err := NewWithPorts(rt, eg, NewInMemoryEngineRunner(), "console7", nil)
	if err != nil {
		t.Fatalf("NewWithPorts: %v", err)
	}
	p.SetCredentialDeliverer(NewInMemoryCredentialDeliverer())
	h, err := p.ProvisionSandbox(context.Background(), interfaces.SandboxSpec{
		SessionID: "sess-1", Subject: "alice@example.test", Persona: interfaces.PersonaAuthor,
		Egress: interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}}, MaxTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("ProvisionSandbox: %v", err)
	}
	eg.SetFailSet(true)
	// Widen attempt: a new destination triggers the deny-all fallback, which fails → taint.
	_ = p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal", "https://b.internal"}})
	if p.Owns(h, "alice@example.test", "sess-1") {
		t.Error("a tainted sandbox (perimeter not guaranteed) must not be owned")
	}
	if p.DeliverIfOwned(h, "alice@example.test", "sess-1", []byte("k")) {
		t.Error("DeliverIfOwned must refuse a tainted sandbox")
	}
}
