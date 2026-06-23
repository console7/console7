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
	// Widening — re-adding a now-removed destination — must be refused AND fail closed to
	// deny-all (the sandbox must not retain its prior reach after a rejected update).
	if err := cloud.ApplyEgressPolicy(ctx, h, interfaces.EgressPolicy{Allowlist: []string{"https://a", "https://b"}}); err == nil {
		t.Error("expected widening egress beyond the current allowlist to be refused")
	}
	if got, ok := cloud.EgressOf(h); !ok || len(got) != 0 {
		t.Errorf("expected egress to fail closed to deny-all after a refused widen, got %v (ok=%v)", got, ok)
	}
}

func TestSandboxRegistry_DeliverIfOwned_FailsClosed(t *testing.T) {
	reg := NewSandboxRegistry()
	h := reg.Provision("alice", "s1")
	// Wrong owner / unknown handle / destroyed handle all fail closed.
	if reg.DeliverIfOwned(h, "mallory", "s1", []byte("x")) {
		t.Error("delivered to a sandbox owned by a different subject")
	}
	if reg.DeliverIfOwned(interfaces.SandboxHandle{ID: "nope"}, "alice", "s1", []byte("x")) {
		t.Error("delivered to an unknown sandbox")
	}
	if !reg.DeliverIfOwned(h, "alice", "s1", []byte("x")) {
		t.Error("refused delivery to the legitimate owner")
	}
	reg.Destroy(h)
	if reg.DeliverIfOwned(h, "alice", "s1", []byte("x")) {
		t.Error("delivered into a destroyed sandbox")
	}
}

func TestSandboxRegistry_ExpiredOwnershipFailsClosed(t *testing.T) {
	reg := NewSandboxRegistry()
	h := reg.ProvisionWithExpiry("alice", "s1", time.Now().Add(time.Nanosecond))
	time.Sleep(2 * time.Millisecond)
	if reg.Owns(h, "alice", "s1") {
		t.Error("expired ownership binding still reports as owned")
	}
	if reg.DeliverIfOwned(h, "alice", "s1", []byte("x")) {
		t.Error("delivered into an expired sandbox (injection must fail closed past MaxTTL)")
	}
}

func TestMemCloud_MaxTTL_ExpiresSandbox(t *testing.T) {
	cloud, _ := newMemCloud()
	ctx := context.Background()
	spec := provisionSpec("s1", "https://a")
	spec.MaxTTL = time.Nanosecond // expires effectively immediately.
	h, err := cloud.ProvisionSandbox(ctx, spec)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	time.Sleep(2 * time.Millisecond) // well past a 1ns TTL.
	if cloud.Live(h) {
		t.Error("sandbox still live past its MaxTTL")
	}
	if err := cloud.ApplyEgressPolicy(ctx, h, interfaces.EgressPolicy{Allowlist: nil}); err == nil {
		t.Error("expected egress changes on an expired sandbox to fail closed")
	}
	if err := cloud.DestroySandbox(ctx, h); err == nil {
		t.Error("expected destroy of an expired sandbox to fail closed")
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

func TestMemCloud_RunTask_DeterministicAndFailsClosed(t *testing.T) {
	cloud, _ := newMemCloud()
	ctx := context.Background()
	task := interfaces.EngineTask{
		SessionID: "s1",
		Profile:   interfaces.SessionProfile{Persona: interfaces.PersonaAuthor},
		Repo:      interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:    "feature/x",
		Prompt:    "do the work",
		Timeout:   time.Minute,
	}

	// Fail closed: a task must not run in an unknown sandbox.
	if _, err := cloud.RunTask(ctx, interfaces.SandboxHandle{ID: "nope"}, task); err == nil {
		t.Fatal("expected RunTask to fail closed on an unknown sandbox")
	}

	h, err := cloud.ProvisionSandbox(ctx, provisionSpec("s1", "https://a"))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// A live sandbox yields a deterministic, non-empty changed result.
	res1, err := cloud.RunTask(ctx, h, task)
	if err != nil {
		t.Fatalf("RunTask: %v", err)
	}
	if !res1.Changed || len(res1.CommitDigest) == 0 || res1.HeadSHA == "" {
		t.Fatalf("expected a changed result with a digest and head, got %+v", res1)
	}
	// LastTask captures the RunTask input (the test-only hook the orchestrator test uses to assert
	// the inference lane/env it threaded).
	if got := cloud.LastTask(); got.SessionID != task.SessionID || got.Branch != task.Branch {
		t.Errorf("LastTask did not capture the run input: got %+v", got)
	}
	// Deterministic over the same coordinates (offline, reproducible — the bench stand-in role).
	res2, err := cloud.RunTask(ctx, h, task)
	if err != nil {
		t.Fatalf("RunTask (second): %v", err)
	}
	if string(res1.CommitDigest) != string(res2.CommitDigest) {
		t.Error("MemCloud.RunTask digest is not deterministic over the same task")
	}

	// No run after destroy.
	if err := cloud.DestroySandbox(ctx, h); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := cloud.RunTask(ctx, h, task); err == nil {
		t.Fatal("expected RunTask to fail closed in a destroyed sandbox")
	}
}
