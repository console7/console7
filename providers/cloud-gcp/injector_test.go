package cloudgcp

import (
	"context"
	"strings"
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

func TestCredentialDeliverWipeArgv_Shape(t *testing.T) {
	h := interfaces.SandboxHandle{ID: "console7-sb-abc"}
	deliver := strings.Join(credentialDeliverArgv(h), " ")
	for _, want := range []string{"-n console7-sb-abc", "-c sandbox", "-i", "umask 077; cat > " + credentialPath} {
		if !strings.Contains(deliver, want) {
			t.Errorf("deliver argv missing %q: %s", want, deliver)
		}
	}
	// The material is delivered over STDIN — it is NEVER in the argv (there is no material parameter to
	// the argv builder), so no secret-shaped token can appear in the process table / this adapter's logs.
	for _, secretish := range []string{"sk-ant", "ANTHROPIC_API_KEY", "BEGIN ", "token"} {
		if strings.Contains(deliver, secretish) {
			t.Errorf("deliver argv unexpectedly contains secret-shaped %q: %s", secretish, deliver)
		}
	}
	wipe := strings.Join(credentialWipeArgv(h), " ")
	if !strings.Contains(wipe, "rm -f "+credentialPath) {
		t.Errorf("wipe argv must rm -f the credential path: %s", wipe)
	}
	if containsArg(credentialWipeArgv(h), "-i") {
		t.Errorf("wipe must not open STDIN (-i): %s", wipe)
	}
}

func containsArg(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

func TestProvider_CredentialAudit(t *testing.T) {
	p, _ := newProviderWithDeliverer(t)
	type ev struct {
		event, id string
		ok        bool
	}
	var events []ev
	p.SetCredentialAudit(func(event, id string, ok bool) { events = append(events, ev{event, id, ok}) })

	h := provisionFor(t, p, "alice@example.test", "sess-1")
	// deny (non-owner) → "deny"; deliver (owner) → "deliver" ok; destroy → "wipe".
	p.DeliverIfOwned(h, "mallory@example.test", "sess-1", []byte("k"))
	p.DeliverIfOwned(h, "alice@example.test", "sess-1", []byte("sk-ant-secret"))
	if err := p.DestroySandbox(context.Background(), h); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}

	seen := map[string]bool{}
	for _, e := range events {
		seen[e.event] = true
		if e.id != h.ID {
			t.Errorf("audit %q carried the wrong handle id %q (want %q)", e.event, e.id, h.ID)
		}
	}
	for _, want := range []string{"deny", "deliver", "wipe"} {
		if !seen[want] {
			t.Errorf("missing %q audit event; got %+v", want, events)
		}
	}
	// Redaction-safety is structural: the hook signature carries (event, handleID, ok) — there is no
	// material parameter, so a credential can never be logged through it.
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
