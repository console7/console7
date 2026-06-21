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

// InMemoryEgressController records the allowlist set for each handle and can be told to fail Set.
type InMemoryEgressController struct {
	mu      sync.Mutex
	policy  map[string][]string
	cleared map[string]bool
	failSet bool
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
	if e.failSet {
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

// SetFailSet toggles forced Set failure. Test-only.
func (e *InMemoryEgressController) SetFailSet(b bool) { e.mu.Lock(); e.failSet = b; e.mu.Unlock() }
