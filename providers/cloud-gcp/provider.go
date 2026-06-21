package cloudgcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// Provider is the reference CloudProvider. It holds the control-side lifecycle state and
// enforces the seam's SECURITY invariants in Go, threading each cloud effect to a port. It
// holds NO standing credential of its own and NO key — the adapter authenticates to the
// cluster via the adopter's ambient gcloud/Workload-Identity context, never a stored secret.
//
// CONCURRENCY: every method takes p.mu for the whole of its decision-AND-effect, so a destroy
// can never interleave with a provision/apply on the same handle and leave the in-memory view
// disagreeing with the cloud. That serialises port I/O under the lock — a deliberate
// reference-impl simplification favouring atomicity over throughput, the same choice
// providers/secrets-gcp made (and Codex required) for its remote-store effects. A production
// build would shard the lock per handle; the seam does not change.
type Provider struct {
	mu        sync.Mutex
	runtime   SandboxRuntime
	egress    EgressController
	prefix    string
	now       func() time.Time
	newID     func() (string, error)
	sandboxes map[string]*sandboxState

	// kubeconfigPath is the private kubeconfig New created for the real adapters; Close removes
	// it. Empty for a Provider built by NewWithPorts (tests/conformance), where Close is a no-op.
	kubeconfigPath string
}

// sandboxState is the lifecycle state the provider tracks for one provisioned sandbox.
type sandboxState struct {
	session interfaces.SessionID
	subject interfaces.Subject
	persona interfaces.Persona
	egress  []string // the default-deny allowlist currently in force at the perimeter.
	expiry  time.Time
	live    bool
}

// NewWithPorts builds a Provider over explicit ports. It is the constructor the conformance
// harness, the unit tests, and (later) the orchestrator use; New wires the real kubectl/gcloud
// adapters into it. A nil now defaults to time.Now; a nil newID defaults to a crypto/rand
// handle generator; nil ports are rejected (a Provider with no runtime/egress would fail open).
func NewWithPorts(runtime SandboxRuntime, egress EgressController, prefix string, now func() time.Time) (*Provider, error) {
	if runtime == nil || egress == nil {
		return nil, errors.New("cloudgcp: NewWithPorts requires a non-nil SandboxRuntime and EgressController")
	}
	if prefix == "" {
		prefix = DefaultNamePrefix
	}
	if now == nil {
		now = time.Now
	}
	return &Provider{
		runtime:   runtime,
		egress:    egress,
		prefix:    prefix,
		now:       now,
		newID:     randomID(prefix),
		sandboxes: make(map[string]*sandboxState),
	}, nil
}

// randomID returns a generator of DNS-1123-label-safe handle IDs ("<prefix>-sb-<12 hex>"),
// unique per call via crypto/rand so a sandbox handle is NEVER reused across sessions, users,
// or personas — uniqueness is by construction, not by keying on a caller-supplied field a
// confused caller could repeat.
func randomID(prefix string) func() (string, error) {
	return func() (string, error) {
		var b [6]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("cloudgcp: generate sandbox id: %w", err)
		}
		return prefix + "-sb-" + hex.EncodeToString(b[:]), nil
	}
}

// ProvisionSandbox creates a per-session, isolated, ephemeral sandbox enforcing spec's
// default-deny egress from the moment it exists.
func (p *Provider) ProvisionSandbox(ctx context.Context, spec interfaces.SandboxSpec) (interfaces.SandboxHandle, error) {
	// Ephemeral by default: refuse a non-positive lifetime rather than provision an unbounded
	// sandbox (a missing MaxTTL is a misconfiguration, not "lives forever").
	if spec.MaxTTL <= 0 {
		return interfaces.SandboxHandle{}, errors.New("cloudgcp: SandboxSpec.MaxTTL must be positive (ephemeral by default)")
	}
	id, err := p.newID()
	if err != nil {
		return interfaces.SandboxHandle{}, err
	}
	h := interfaces.SandboxHandle{ID: id}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Perimeter BEFORE workload (cloud.go SECURITY): set the default-deny egress allowlist at
	// the out-of-band perimeter first, so there is never a window where the workload exists but
	// the perimeter does not. If the perimeter cannot be set, nothing is provisioned — fail closed.
	allowlist := append([]string(nil), spec.Egress.Allowlist...)
	if err := p.egress.Set(ctx, h, allowlist); err != nil {
		return interfaces.SandboxHandle{}, fmt.Errorf("cloudgcp: set egress perimeter before provision: %w", err)
	}
	// Now provision the isolated compute. If it fails, tear the perimeter back down so we do not
	// leak a configured-but-unused perimeter, and surface the error.
	if err := p.runtime.Provision(ctx, h, spec); err != nil {
		if cerr := p.egress.Clear(ctx, h); cerr != nil {
			err = errors.Join(err, fmt.Errorf("cloudgcp: clear perimeter after failed provision: %w", cerr))
		}
		return interfaces.SandboxHandle{}, fmt.Errorf("cloudgcp: provision sandbox: %w", err)
	}
	p.sandboxes[id] = &sandboxState{
		session: spec.SessionID,
		subject: spec.Subject,
		persona: spec.Persona,
		egress:  allowlist,
		expiry:  p.now().Add(spec.MaxTTL),
		live:    true,
	}
	return h, nil
}

// ApplyEgressPolicy narrows (never widens) the egress allowlist for a live sandbox.
func (p *Provider) ApplyEgressPolicy(ctx context.Context, h interfaces.SandboxHandle, policy interfaces.EgressPolicy) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	sb, ok := p.lookup(h)
	if !ok || !sb.live {
		// Fail closed: an unknown, destroyed, or expired sandbox has no perimeter to narrow.
		return errors.New("cloudgcp: cannot apply egress to an unknown, destroyed, or expired sandbox")
	}
	// Narrow-only: a permissive origin MUST NOT confer a stricter target's reach, so an update
	// may only REMOVE destinations, never add one beyond those already permitted. A widening
	// request cannot be honoured, so the sandbox fails CLOSED — its perimeter drops to deny-all
	// rather than keeping its prior (now-suspect) reach — and the call errors.
	allowed := make(map[string]bool, len(sb.egress))
	for _, d := range sb.egress {
		allowed[d] = true
	}
	for _, d := range policy.Allowlist {
		if !allowed[d] {
			sb.egress = nil
			err := p.egress.Set(ctx, h, nil) // enforce deny-all at the perimeter.
			return errors.Join(errors.New("cloudgcp: refused to widen egress beyond the provisioned allowlist; egress denied"), err)
		}
	}
	next := append([]string(nil), policy.Allowlist...)
	if err := p.egress.Set(ctx, h, next); err != nil {
		// Could not apply the narrowed policy — fail closed to deny-all, do not leave the old
		// allowlist in force.
		sb.egress = nil
		_ = p.egress.Set(ctx, h, nil)
		return fmt.Errorf("cloudgcp: apply narrowed egress (failed closed to deny-all): %w", err)
	}
	sb.egress = next
	return nil
}

// DestroySandbox irreversibly tears the sandbox down and wipes any injected material.
func (p *Provider) DestroySandbox(ctx context.Context, h interfaces.SandboxHandle) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	sb, ok := p.lookup(h)
	if !ok || !sb.live {
		// Destroying an unknown, already-destroyed, or expired sandbox fails closed — the
		// caller's view of what exists is wrong, and silently succeeding would mask it. (An
		// expired sandbox was already marked dead by lookup.)
		return errors.New("cloudgcp: cannot destroy an unknown, already-destroyed, or expired sandbox")
	}
	// Tear the workload down FIRST (stop the thing that could act), then clear its perimeter. A
	// runtime-destroy failure is fatal and is NOT marked dead — the sandbox may still be live, so
	// the caller (and a retry) must see it as live, exactly as the orchestrator's abort path
	// surfaces a failed destroy rather than assuming the sandbox is gone.
	if err := p.runtime.Destroy(ctx, h); err != nil {
		return fmt.Errorf("cloudgcp: destroy sandbox (may still be live): %w", err)
	}
	// The workload is gone; mark dead so any later operation fails closed. A Clear failure now
	// only leaves orphaned perimeter config (harmless — nothing routes through it), so it is
	// joined and surfaced but does not resurrect the sandbox.
	sb.live = false
	sb.egress = nil
	if err := p.egress.Clear(ctx, h); err != nil {
		return fmt.Errorf("cloudgcp: sandbox destroyed but clearing its perimeter failed: %w", err)
	}
	return nil
}

// lookup returns the state for h, marking it dead first if it has aged past its MaxTTL so a
// caller sees an expired sandbox as not live (fail closed). The real workload also carries a
// hard activeDeadlineSeconds from MaxTTL, so an expired-but-not-yet-destroyed sandbox dies at
// the cloud too; this lazy check keeps the provider's own surface fail-closed in the interim.
// The caller must hold p.mu.
func (p *Provider) lookup(h interfaces.SandboxHandle) (*sandboxState, bool) {
	sb, ok := p.sandboxes[h.ID]
	if !ok {
		return nil, false
	}
	if sb.live && !p.now().Before(sb.expiry) {
		sb.live = false
		sb.egress = nil
	}
	return sb, true
}

// Live reports whether h is a known, not-yet-destroyed, not-yet-expired sandbox. Test-only
// inspection hook (matches sdk/devkit.MemCloud.Live).
func (p *Provider) Live(h interfaces.SandboxHandle) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	sb, ok := p.lookup(h)
	return ok && sb.live
}

// EgressOf returns the egress allowlist currently in force for an operable sandbox. Test-only.
func (p *Provider) EgressOf(h interfaces.SandboxHandle) ([]string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sb, ok := p.lookup(h)
	if !ok || !sb.live {
		return nil, false
	}
	return append([]string(nil), sb.egress...), true
}
