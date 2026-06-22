package cloudgcp

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// newTestProvider builds a Provider over fresh fakes with a deterministic, monotonic handle
// generator (so a test can name the handle it provisioned) and an injectable clock.
func newTestProvider(t *testing.T, now func() time.Time) (*Provider, *InMemorySandboxRuntime, *InMemoryEgressController) {
	t.Helper()
	rt := NewInMemorySandboxRuntime()
	eg := NewInMemoryEgressController()
	p, err := NewWithPorts(rt, eg, NewInMemoryEngineRunner(), "test", now)
	if err != nil {
		t.Fatalf("NewWithPorts: %v", err)
	}
	var n int
	p.newID = func() (string, error) { n++; return "test-sb-" + strconv.Itoa(n), nil }
	return p, rt, eg
}

func baseSpec() interfaces.SandboxSpec {
	return interfaces.SandboxSpec{
		SessionID: "sess",
		Subject:   "alice@example.test",
		Persona:   interfaces.PersonaAuthor,
		Egress:    interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}},
		MaxTTL:    time.Minute,
	}
}

func TestRandomID_FormatAndDistinct(t *testing.T) {
	gen := randomID("console7")
	seen := make(map[string]bool)
	for range 100 {
		id, err := gen()
		if err != nil {
			t.Fatalf("randomID: %v", err)
		}
		// "<prefix>-sb-<32 hex>" — DNS-1123-label-safe and bounded under 63 chars.
		if !strings.HasPrefix(id, "console7-sb-") || len(id) != len("console7-sb-")+32 {
			t.Fatalf("unexpected id shape: %q (len %d)", id, len(id))
		}
		if len(id) > 63 {
			t.Fatalf("id exceeds the DNS-1123 label limit: %q", id)
		}
		if seen[id] {
			t.Fatalf("randomID returned a duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestClose(t *testing.T) {
	// A provider built by NewWithPorts holds no kubeconfig: Close is a no-op and idempotent.
	p, err := NewWithPorts(NewInMemorySandboxRuntime(), NewInMemoryEgressController(), NewInMemoryEngineRunner(), "p", nil)
	if err != nil {
		t.Fatalf("NewWithPorts: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close on a portless provider should be a no-op: %v", err)
	}

	// With a kubeconfig path set, Close removes the file and is idempotent (tolerates a missing file).
	f, err := os.CreateTemp(t.TempDir(), "kubeconfig-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	path := f.Name()
	_ = f.Close()
	p.kubeconfigPath = path
	if err := p.Close(); err != nil {
		t.Fatalf("Close removing the kubeconfig: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("kubeconfig not removed by Close: stat err=%v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close should be a no-op: %v", err)
	}
}

func TestNewWithPorts_RejectsNilPorts(t *testing.T) {
	if _, err := NewWithPorts(nil, NewInMemoryEgressController(), NewInMemoryEngineRunner(), "p", nil); err == nil {
		t.Fatal("expected error for nil runtime")
	}
	if _, err := NewWithPorts(NewInMemorySandboxRuntime(), nil, NewInMemoryEngineRunner(), "p", nil); err == nil {
		t.Fatal("expected error for nil egress controller")
	}
	if _, err := NewWithPorts(NewInMemorySandboxRuntime(), NewInMemoryEgressController(), nil, "p", nil); err == nil {
		t.Fatal("expected error for nil engine runner")
	}
}

func TestProvision_RejectsNonPositiveTTL(t *testing.T) {
	p, rt, _ := newTestProvider(t, nil)
	spec := baseSpec()
	spec.MaxTTL = 0
	if _, err := p.ProvisionSandbox(context.Background(), spec); err == nil {
		t.Fatal("expected error for zero MaxTTL")
	}
	if rt.Provisioned(interfaces.SandboxHandle{ID: "test-sb-1"}) {
		t.Fatal("a sandbox was provisioned despite a rejected TTL")
	}
}

func TestProvision_SetsPerimeterThenWorkload(t *testing.T) {
	p, rt, eg := newTestProvider(t, nil)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if !rt.Provisioned(h) {
		t.Fatal("runtime did not record the provisioned sandbox")
	}
	got, ok := eg.PolicyOf(h)
	if !ok || len(got) != 1 || got[0] != "https://a.internal" {
		t.Fatalf("perimeter not set to the spec allowlist: %v ok=%v", got, ok)
	}
	if !p.Live(h) {
		t.Fatal("sandbox not live after provision")
	}
}

func TestProvision_FailsClosedIfPerimeterCannotBeSet(t *testing.T) {
	p, rt, eg := newTestProvider(t, nil)
	eg.SetFailSet(true)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err == nil {
		t.Fatal("expected provision to fail when the perimeter cannot be set")
	}
	if h.ID != "" {
		t.Fatalf("returned a non-empty handle on failure: %q", h.ID)
	}
	// Perimeter-before-workload: the workload must NOT have been provisioned.
	if rt.Provisioned(interfaces.SandboxHandle{ID: "test-sb-1"}) {
		t.Fatal("workload was provisioned even though the perimeter could not be set")
	}
}

func TestProvision_RollsBackPerimeterIfWorkloadFails(t *testing.T) {
	p, rt, eg := newTestProvider(t, nil)
	rt.SetFailProvision(true)
	if _, err := p.ProvisionSandbox(context.Background(), baseSpec()); err == nil {
		t.Fatal("expected provision to fail when the workload cannot start")
	}
	// The perimeter set before the failed workload must have been cleared (no orphan).
	if _, ok := eg.PolicyOf(interfaces.SandboxHandle{ID: "test-sb-1"}); ok {
		t.Fatal("perimeter was left configured after a failed workload provision")
	}
}

func TestProvision_ClearsPerimeterIfEgressSetFails(t *testing.T) {
	p, _, eg := newTestProvider(t, nil)
	eg.SetFailSet(true)
	if _, err := p.ProvisionSandbox(context.Background(), baseSpec()); err == nil {
		t.Fatal("expected provision to fail when the egress perimeter cannot be set")
	}
	// Set now provisions TWO namespaces (the per-session proxy + the sandbox perimeter); a partial
	// Set must be rolled back via Clear so the proxy namespace is not orphaned (the handle id is
	// deterministic in the test rig — the first provision is test-sb-1).
	if !eg.Cleared(interfaces.SandboxHandle{ID: "test-sb-1"}) {
		t.Fatal("a failed egress Set was not rolled back (the per-session proxy namespace would orphan)")
	}
}

func TestProvision_FreshHandlePerCall(t *testing.T) {
	p, _, _ := newTestProvider(t, nil)
	h1, _ := p.ProvisionSandbox(context.Background(), baseSpec())
	h2, _ := p.ProvisionSandbox(context.Background(), baseSpec())
	if h1.ID == "" || h2.ID == "" || h1.ID == h2.ID {
		t.Fatalf("expected two distinct non-empty handles, got %q and %q", h1.ID, h2.ID)
	}
}

func TestApplyEgress_NarrowsButNeverWidens(t *testing.T) {
	p, _, eg := newTestProvider(t, nil)
	spec := baseSpec()
	spec.Egress.Allowlist = []string{"https://a.internal", "https://b.internal"}
	h, err := p.ProvisionSandbox(context.Background(), spec)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Narrowing to a subset succeeds and is pushed to the perimeter.
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}}); err != nil {
		t.Fatalf("narrow should succeed: %v", err)
	}
	if got, _ := eg.PolicyOf(h); len(got) != 1 || got[0] != "https://a.internal" {
		t.Fatalf("perimeter not narrowed: %v", got)
	}
	// Widening (a destination not in the provisioned set) must fail closed to deny-all.
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal", "https://evil.internal"}}); err == nil {
		t.Fatal("expected a widening policy to be refused")
	}
	if got, _ := eg.PolicyOf(h); len(got) != 0 {
		t.Fatalf("perimeter not failed closed to deny-all after a widen attempt: %v", got)
	}
	if got, ok := p.EgressOf(h); !ok || len(got) != 0 {
		t.Fatalf("provider state not deny-all after widen: %v ok=%v", got, ok)
	}
}

func TestApplyEgress_FailsClosedOnUnknownHandle(t *testing.T) {
	p, _, _ := newTestProvider(t, nil)
	if err := p.ApplyEgressPolicy(context.Background(), interfaces.SandboxHandle{ID: "nope"}, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}}); err == nil {
		t.Fatal("expected fail-closed on an unknown handle")
	}
}

func TestApplyEgress_TotalSetFailureDoesNotClaimDenyAll(t *testing.T) {
	p, _, eg := newTestProvider(t, nil)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec()) // provisioned egress [a.internal]
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	eg.SetFailSet(true)
	// A valid narrow, but BOTH the narrowed Set and the deny-all fallback fail → error.
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: nil}); err == nil {
		t.Fatal("expected an error when neither the narrow nor the deny-all fallback can apply")
	}
	// The provider must NOT falsely claim a deny-all it could not apply: in-memory egress stays
	// matching the cluster's still-live prior policy (the error is what forces teardown).
	if got, ok := p.EgressOf(h); !ok || len(got) != 1 || got[0] != "https://a.internal" {
		t.Fatalf("expected unchanged egress (no false deny-all) after a total Set failure, got %v ok=%v", got, ok)
	}
}

func TestApplyEgress_NarrowFailsButDenyAllApplies(t *testing.T) {
	p, _, eg := newTestProvider(t, nil)
	spec := baseSpec()
	spec.Egress.Allowlist = []string{"https://a.internal", "https://b.internal"}
	h, err := p.ProvisionSandbox(context.Background(), spec)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Narrowed (non-empty) Sets fail, but the deny-all fallback succeeds → error, and the perimeter
	// IS deny-all (truthfully recorded, because that Set actually applied).
	eg.SetFailNonEmptySet(true)
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}}); err == nil {
		t.Fatal("expected an error when the narrowed policy cannot apply")
	}
	if got, ok := p.EgressOf(h); !ok || len(got) != 0 {
		t.Fatalf("expected deny-all (the fallback applied), got %v ok=%v", got, ok)
	}
	if got, _ := eg.PolicyOf(h); len(got) != 0 {
		t.Fatalf("perimeter not deny-all at the controller: %v", got)
	}
}

func TestApplyEgress_WidenFailsClosedWhenDenyAllAlsoFails(t *testing.T) {
	p, _, eg := newTestProvider(t, nil)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec()) // [a.internal]
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	eg.SetFailSet(true)
	// A widen attempt whose deny-all fallback also fails must still error (never silently widen).
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal", "https://evil.internal"}}); err == nil {
		t.Fatal("expected a widen with a failing deny-all fallback to error")
	}
}

func TestApplyEgress_TaintsWhenPerimeterUnenforceable(t *testing.T) {
	p, _, eg := newTestProvider(t, nil)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// The deny-all fallback cannot apply → the sandbox is tainted (perimeter unknown).
	eg.SetFailSet(true)
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: nil}); err == nil {
		t.Fatal("expected an error when the perimeter cannot be enforced")
	}
	// A tainted sandbox refuses any further egress change (even now that Set works again)...
	eg.SetFailSet(false)
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: nil}); err == nil {
		t.Fatal("expected a tainted sandbox to refuse further egress changes")
	}
	// ...but teardown is still permitted, so the caller can reclaim it.
	if err := p.DestroySandbox(context.Background(), h); err != nil {
		t.Fatalf("teardown of a tainted sandbox must be permitted: %v", err)
	}
	if p.Live(h) {
		t.Fatal("sandbox still live after teardown")
	}
}

func TestDestroy_IsIrreversible(t *testing.T) {
	p, rt, _ := newTestProvider(t, nil)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := p.DestroySandbox(context.Background(), h); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if rt.Provisioned(h) {
		t.Fatal("runtime still reports the sandbox as live after destroy")
	}
	if p.Live(h) {
		t.Fatal("provider still reports the sandbox as live after destroy")
	}
	// A second destroy, or an egress change, must fail closed — never resurrect it.
	if err := p.DestroySandbox(context.Background(), h); err == nil {
		t.Fatal("expected a second destroy to fail closed")
	}
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: nil}); err == nil {
		t.Fatal("expected an egress change on a destroyed sandbox to fail closed")
	}
}

func TestDestroy_RuntimeFailureLeavesSandboxLive(t *testing.T) {
	p, rt, _ := newTestProvider(t, nil)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	rt.SetFailDestroy(true)
	if err := p.DestroySandbox(context.Background(), h); err == nil {
		t.Fatal("expected destroy to surface the runtime failure")
	}
	// The sandbox may still be live, so the provider must NOT mark it dead — a retry must work.
	if !p.Live(h) {
		t.Fatal("a failed destroy wrongly marked the sandbox dead (it may still be live)")
	}
	rt.SetFailDestroy(false)
	if err := p.DestroySandbox(context.Background(), h); err != nil {
		t.Fatalf("retry destroy should succeed: %v", err)
	}
	if p.Live(h) {
		t.Fatal("sandbox still live after a successful retry destroy")
	}
}

func TestDestroy_FailsClosedOnUnknownHandle(t *testing.T) {
	p, _, _ := newTestProvider(t, nil)
	if err := p.DestroySandbox(context.Background(), interfaces.SandboxHandle{ID: "nope"}); err == nil {
		t.Fatal("expected fail-closed on destroying an unknown handle")
	}
}

func TestExpiry_FailsClosedAfterTTL(t *testing.T) {
	clock := time.Unix(1000, 0)
	p, _, _ := newTestProvider(t, func() time.Time { return clock })
	spec := baseSpec()
	spec.MaxTTL = time.Minute
	h, err := p.ProvisionSandbox(context.Background(), spec)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if !p.Live(h) {
		t.Fatal("sandbox should be live immediately after provision")
	}
	// Advance the clock past the TTL.
	clock = clock.Add(2 * time.Minute)
	if p.Live(h) {
		t.Fatal("sandbox should be reaped (not live) past its MaxTTL")
	}
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: nil}); err == nil {
		t.Fatal("expected egress change on an expired sandbox to fail closed")
	}
	if err := p.DestroySandbox(context.Background(), h); err == nil {
		t.Fatal("expected destroy of an expired sandbox to fail closed")
	}
}

func TestProvision_PropagatesIDGeneratorError(t *testing.T) {
	p, _, _ := newTestProvider(t, nil)
	p.newID = func() (string, error) { return "", errors.New("boom") }
	if _, err := p.ProvisionSandbox(context.Background(), baseSpec()); err == nil {
		t.Fatal("expected provision to surface a handle-generation error")
	}
}

func TestProvision_FreshIDRetriesPastACollision(t *testing.T) {
	p, _, _ := newTestProvider(t, nil)
	// First provision takes "dup"; the next generator run returns "dup" again (collision) then a
	// fresh id — freshID must skip the in-use id and yield the fresh one.
	ids := []string{"dup", "dup", "fresh"}
	var i int
	p.newID = func() (string, error) { id := ids[i]; i++; return id, nil }
	h1, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil || h1.ID != "dup" {
		t.Fatalf("first provision: handle=%q err=%v", h1.ID, err)
	}
	h2, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if h2.ID != "fresh" {
		t.Fatalf("freshID did not skip the in-use id: got %q, want fresh", h2.ID)
	}
}

func TestProvision_FreshIDExhaustionErrors(t *testing.T) {
	p, _, _ := newTestProvider(t, nil)
	if _, err := p.ProvisionSandbox(context.Background(), baseSpec()); err != nil {
		t.Fatalf("seed provision: %v", err)
	}
	// The generator now always returns the already-used id; freshID must give up (not loop forever)
	// and surface an error rather than collide.
	p.newID = func() (string, error) { return "test-sb-1", nil }
	// Seed used "test-sb-1" (the deterministic first id), so every retry collides.
	if _, err := p.ProvisionSandbox(context.Background(), baseSpec()); err == nil {
		t.Fatal("expected freshID exhaustion to error after repeated collisions")
	}
}

// engineTestProvider builds a provider over fresh fakes including a held EngineRunner, so a test
// can assert what (if anything) RunTask handed to the runner.
func engineTestProvider(t *testing.T) (*Provider, *InMemoryEgressController, *InMemoryEngineRunner) {
	t.Helper()
	rt := NewInMemorySandboxRuntime()
	eg := NewInMemoryEgressController()
	runner := NewInMemoryEngineRunner()
	p, err := NewWithPorts(rt, eg, runner, "test", nil)
	if err != nil {
		t.Fatalf("NewWithPorts: %v", err)
	}
	return p, eg, runner
}

func engineTask() interfaces.EngineTask {
	return interfaces.EngineTask{
		SessionID: "sess",
		Profile:   interfaces.SessionProfile{Persona: interfaces.PersonaAuthor},
		Repo:      interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:    "feature/x",
		Prompt:    "do the work",
		Timeout:   time.Minute,
	}
}

func TestRunTask_GatesOnLiveSandbox(t *testing.T) {
	p, _, runner := engineTestProvider(t)
	task := engineTask()

	// Unknown handle → fail closed, and the runner is never invoked.
	if _, err := p.RunTask(context.Background(), interfaces.SandboxHandle{ID: "nope"}, task); err == nil {
		t.Fatal("expected fail-closed running a task in an unknown sandbox")
	}
	if _, ran := runner.LastTask(); ran {
		t.Fatal("runner was invoked for an unknown sandbox")
	}

	h, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Live sandbox → the task reaches the runner and a changed result with a digest comes back.
	res, err := p.RunTask(context.Background(), h, task)
	if err != nil {
		t.Fatalf("RunTask in a live sandbox: %v", err)
	}
	if !res.Changed || len(res.CommitDigest) == 0 {
		t.Fatalf("expected a changed result with a non-empty digest, got %+v", res)
	}
	got, ran := runner.LastTask()
	if !ran || got.Branch != "feature/x" || got.SessionID != "sess" {
		t.Fatalf("runner did not receive the task: ran=%v task=%+v", ran, got)
	}

	// No run after destroy: a task must never execute in a torn-down (perimeter-gone) sandbox.
	if err := p.DestroySandbox(context.Background(), h); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := p.RunTask(context.Background(), h, task); err == nil {
		t.Fatal("expected fail-closed running a task in a destroyed sandbox")
	}
}

func TestRunTask_RefusesTaintedSandbox(t *testing.T) {
	p, eg, runner := engineTestProvider(t)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Force a taint: a deny-all fallback that cannot apply leaves the perimeter unknown.
	eg.SetFailSet(true)
	if err := p.ApplyEgressPolicy(context.Background(), h, interfaces.EgressPolicy{Allowlist: nil}); err == nil {
		t.Fatal("expected the unenforceable perimeter to error")
	}
	eg.SetFailSet(false)
	// A tainted sandbox must refuse RunTask (its perimeter is not guaranteed) without invoking the engine.
	if _, err := p.RunTask(context.Background(), h, engineTask()); err == nil {
		t.Fatal("expected a tainted sandbox to refuse RunTask")
	}
	if _, ran := runner.LastTask(); ran {
		t.Fatal("runner was invoked for a tainted sandbox")
	}
}

func TestRunTask_SurfacesRunnerFailure(t *testing.T) {
	p, _, runner := engineTestProvider(t)
	runner.SetFailRun(true)
	h, err := p.ProvisionSandbox(context.Background(), baseSpec())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := p.RunTask(context.Background(), h, engineTask()); err == nil {
		t.Fatal("expected RunTask to surface the runner failure")
	}
}
