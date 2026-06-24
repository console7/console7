package cloudgcp

import (
	"context"
	"errors"
	"sync"

	"github.com/console7/console7/sdk/interfaces"
)

// This file provides NON-PRODUCTION in-memory implementations of the provider's ports. They
// let provider_test.go and the conformance harness exercise the full CloudProvider lifecycle
// logic — and its SECURITY invariants — with no GCP project and no credentials. New NEVER wires
// one of these; only NewWithPorts (tests, conformance, out-of-tree provider authors) does.
//
// The fakes are deliberately thin EFFECT RECORDERS: they do not re-implement any contract
// invariant (ordering, narrow-only, irreversibility) — that logic lives in provider.go and is
// what the conformance suite asserts THROUGH the CloudProvider interface. The fakes only record
// what the provider asked the cloud to do, and expose test-only hooks to force failures so the
// provider's fail-closed paths can be driven. A real adapter has no such hooks.

// InMemorySandboxRuntime records provision/destroy calls and can be told to fail either.
type InMemorySandboxRuntime struct {
	mu          sync.Mutex
	provisioned map[string]interfaces.SandboxSpec
	destroyed   map[string]bool
	failProvision,
	failDestroy bool
}

// NewInMemorySandboxRuntime returns a ready InMemorySandboxRuntime.
func NewInMemorySandboxRuntime() *InMemorySandboxRuntime {
	return &InMemorySandboxRuntime{
		provisioned: make(map[string]interfaces.SandboxSpec),
		destroyed:   make(map[string]bool),
	}
}

// Provision records the spec for handle (or fails if SetFailProvision(true)).
func (r *InMemorySandboxRuntime) Provision(_ context.Context, h interfaces.SandboxHandle, spec interfaces.SandboxSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failProvision {
		return errors.New("cloudgcp/fake: forced Provision failure")
	}
	r.provisioned[h.ID] = spec
	return nil
}

// Destroy records the teardown of handle (or fails if SetFailDestroy(true)).
func (r *InMemorySandboxRuntime) Destroy(_ context.Context, h interfaces.SandboxHandle) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failDestroy {
		return errors.New("cloudgcp/fake: forced Destroy failure")
	}
	r.destroyed[h.ID] = true
	return nil
}

// Provisioned reports whether handle was provisioned and not destroyed. Test-only.
func (r *InMemorySandboxRuntime) Provisioned(h interfaces.SandboxHandle) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.provisioned[h.ID]
	return ok && !r.destroyed[h.ID]
}

// SetFailProvision toggles forced Provision failure. Test-only.
func (r *InMemorySandboxRuntime) SetFailProvision(b bool) {
	r.mu.Lock()
	r.failProvision = b
	r.mu.Unlock()
}

// SetFailDestroy toggles forced Destroy failure. Test-only.
func (r *InMemorySandboxRuntime) SetFailDestroy(b bool) {
	r.mu.Lock()
	r.failDestroy = b
	r.mu.Unlock()
}

// InMemoryEgressController records the allowlist set for each handle and can be told to fail Set
// (always, or only for a non-empty allowlist — so a test can model "the narrowed policy can't
// apply but the deny-all fallback can").
type InMemoryEgressController struct {
	mu           sync.Mutex
	policy       map[string][]string
	cleared      map[string]bool
	failSet      bool
	failNonEmpty bool
}

// NewInMemoryEgressController returns a ready InMemoryEgressController.
func NewInMemoryEgressController() *InMemoryEgressController {
	return &InMemoryEgressController{
		policy:  make(map[string][]string),
		cleared: make(map[string]bool),
	}
}

// Set records the allowlist for handle (or fails if SetFailSet(true)).
func (e *InMemoryEgressController) Set(_ context.Context, h interfaces.SandboxHandle, allowlist []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failSet || (e.failNonEmpty && len(allowlist) > 0) {
		return errors.New("cloudgcp/fake: forced Set failure")
	}
	e.policy[h.ID] = append([]string(nil), allowlist...)
	delete(e.cleared, h.ID)
	return nil
}

// Clear records the teardown of handle's perimeter.
func (e *InMemoryEgressController) Clear(_ context.Context, h interfaces.SandboxHandle) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.policy, h.ID)
	e.cleared[h.ID] = true
	return nil
}

// PolicyOf returns the allowlist recorded for handle. Test-only.
func (e *InMemoryEgressController) PolicyOf(h interfaces.SandboxHandle) ([]string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, ok := e.policy[h.ID]
	return append([]string(nil), p...), ok
}

// Cleared reports whether handle's perimeter was torn down via Clear. Test-only (lets a test assert
// the provider rolled back the perimeter — e.g. after a failed egress Set or workload provision).
func (e *InMemoryEgressController) Cleared(h interfaces.SandboxHandle) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cleared[h.ID]
}

// SetFailSet toggles forced Set failure (for any allowlist). Test-only.
func (e *InMemoryEgressController) SetFailSet(b bool) { e.mu.Lock(); e.failSet = b; e.mu.Unlock() }

// SetFailNonEmptySet toggles forced Set failure ONLY for a non-empty allowlist (a deny-all
// Set(nil) still succeeds). Test-only.
func (e *InMemoryEgressController) SetFailNonEmptySet(b bool) {
	e.mu.Lock()
	e.failNonEmpty = b
	e.mu.Unlock()
}

// InMemoryEngineRunner records the last task it was asked to run and returns a deterministic
// EngineResult, so the provider's liveness/taint gate around RunTask is exercised over a
// successful runner. Like the other fakes it is a thin EFFECT RECORDER — it does NOT launch the
// engine (conformance is credential-free and offline); the real adapter (kubeEngineRunner) does.
type InMemoryEngineRunner struct {
	mu       sync.Mutex
	lastTask interfaces.EngineTask
	ran      bool
	failRun  bool
}

// NewInMemoryEngineRunner returns a ready InMemoryEngineRunner.
func NewInMemoryEngineRunner() *InMemoryEngineRunner { return &InMemoryEngineRunner{} }

// Run records task and returns a deterministic, non-empty changed result (or fails if
// SetFailRun(true)). The provider has already guaranteed the sandbox is live when this is called.
func (r *InMemoryEngineRunner) Run(_ context.Context, _ interfaces.SandboxHandle, task interfaces.EngineTask) (interfaces.EngineResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failRun {
		return interfaces.EngineResult{}, errors.New("cloudgcp/fake: forced Run failure")
	}
	r.lastTask = task
	r.ran = true
	// A fixed 32-byte digest stands in for the engine's commit; the provider/orchestrator treat it
	// opaquely, so a constant suffices to exercise the seam (non-empty digest, Changed=true).
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	return interfaces.EngineResult{
		CommitDigest: digest,
		HeadSHA:      "0000000000000000000000000000000000000001",
		FilesChanged: []string{"(cloudgcp fake: no genuine engine run)"},
		Changed:      true,
		// Non-empty stand-in for the working-branch bundle the real runner extracts, so the conformance
		// CommitBundle contract (Changed ⇒ non-empty) holds against the fake too.
		CommitBundle: []byte("cloudgcp-fake-bundle"),
	}, nil
}

// LastTask returns the task most recently passed to Run, for white-box assertions. Test-only.
func (r *InMemoryEngineRunner) LastTask() (interfaces.EngineTask, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastTask, r.ran
}

// SetFailRun toggles forced Run failure, to drive the provider's RunTask error path. Test-only.
func (r *InMemoryEngineRunner) SetFailRun(b bool) { r.mu.Lock(); r.failRun = b; r.mu.Unlock() }

// denyDeliverer is the fail-closed CredentialDeliverer NewWithPorts defaults to: it delivers
// nothing, so a Provider with no real deliverer wired refuses every injection rather than dropping
// material silently. The real adapter is kubeCredentialDeliverer.
type denyDeliverer struct{}

func (denyDeliverer) Deliver(context.Context, interfaces.SandboxHandle, []byte) error {
	return errors.New("cloudgcp: no credential deliverer wired (fail closed)")
}
func (denyDeliverer) Wipe(context.Context, interfaces.SandboxHandle) error { return nil }

// InMemoryCredentialDeliverer records the material delivered per handle (and which handles were
// wiped), so the provider's ownership-gated DeliverIfOwned can be exercised without a cluster. A
// thin effect recorder like the other fakes; it can be told to fail Deliver to drive the
// provider's fail-closed delivery path.
type InMemoryCredentialDeliverer struct {
	mu          sync.Mutex
	delivered   map[string][]byte
	wiped       map[string]bool
	failDeliver bool
}

// NewInMemoryCredentialDeliverer returns a ready InMemoryCredentialDeliverer.
func NewInMemoryCredentialDeliverer() *InMemoryCredentialDeliverer {
	return &InMemoryCredentialDeliverer{delivered: make(map[string][]byte), wiped: make(map[string]bool)}
}

// Deliver records a copy of material for handle (or fails if SetFailDeliver(true)).
func (d *InMemoryCredentialDeliverer) Deliver(_ context.Context, h interfaces.SandboxHandle, material []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failDeliver {
		return errors.New("cloudgcp/fake: forced Deliver failure")
	}
	d.delivered[h.ID] = append([]byte(nil), material...)
	delete(d.wiped, h.ID)
	return nil
}

// Wipe records the shred of handle's material.
func (d *InMemoryCredentialDeliverer) Wipe(_ context.Context, h interfaces.SandboxHandle) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.delivered, h.ID)
	d.wiped[h.ID] = true
	return nil
}

// Delivered returns a copy of the material recorded for handle. Test-only.
func (d *InMemoryCredentialDeliverer) Delivered(h interfaces.SandboxHandle) ([]byte, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, ok := d.delivered[h.ID]
	return append([]byte(nil), m...), ok
}

// Wiped reports whether handle's material was wiped. Test-only.
func (d *InMemoryCredentialDeliverer) Wiped(h interfaces.SandboxHandle) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.wiped[h.ID]
}

// SetFailDeliver toggles forced Deliver failure, to drive DeliverIfOwned's fail-closed path. Test-only.
func (d *InMemoryCredentialDeliverer) SetFailDeliver(b bool) {
	d.mu.Lock()
	d.failDeliver = b
	d.mu.Unlock()
}
