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

// rollbackTimeout bounds the detached perimeter-rollback when a provision fails — long enough for
// a namespace delete to be accepted, short enough not to wedge teardown on an unresponsive API.
const rollbackTimeout = 30 * time.Second

// deliverTimeout bounds a single credential delivery/wipe exec. The Injector seam (Owns /
// DeliverIfOwned) carries no context, so DeliverIfOwned derives a bounded one for the port I/O.
const deliverTimeout = 30 * time.Second

// errWidenRefused is the sentinel an ApplyEgressPolicy returns when a policy would widen the
// allowlist beyond what was provisioned (narrow-only; GOAL.md tenet 4 — a permissive origin must
// not confer a stricter target's reach).
var errWidenRefused = errors.New("cloudgcp: refused to widen egress beyond the provisioned allowlist; egress denied")

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
	runner    EngineRunner
	deliverer CredentialDeliverer
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
	// tainted marks a sandbox whose perimeter could NOT be guaranteed (a deny-all fallback failed):
	// the workload is still running but with a stale/unknown perimeter, so the ONLY operation
	// permitted on it is teardown. ApplyEgressPolicy refuses a tainted sandbox; DestroySandbox does
	// not, so the caller can (and must) reclaim it.
	tainted bool
}

// NewWithPorts builds a Provider over explicit ports. It is the constructor the conformance
// harness, the unit tests, and (later) the orchestrator use; New wires the real kubectl/gcloud
// adapters into it. A nil now defaults to time.Now; a nil newID defaults to a crypto/rand
// handle generator; nil ports are rejected (a Provider with no runtime/egress/runner would fail
// open — a nil runner would let RunTask be called on a Provider that cannot run the engine).
func NewWithPorts(runtime SandboxRuntime, egress EgressController, runner EngineRunner, prefix string, now func() time.Time) (*Provider, error) {
	if runtime == nil || egress == nil || runner == nil {
		return nil, errors.New("cloudgcp: NewWithPorts requires a non-nil SandboxRuntime, EgressController, and EngineRunner")
	}
	if prefix == "" {
		prefix = DefaultNamePrefix
	}
	if now == nil {
		now = time.Now
	}
	return &Provider{
		runtime: runtime,
		egress:  egress,
		runner:  runner,
		// Fail-closed default: a Provider with no real deliverer wired refuses every injection
		// (DeliverIfOwned returns false) rather than silently dropping or mis-delivering material.
		// New wires the kube deliverer; tests/orchestrator call SetCredentialDeliverer.
		deliverer: denyDeliverer{},
		prefix:    prefix,
		now:       now,
		newID:     randomID(prefix),
		sandboxes: make(map[string]*sandboxState),
	}, nil
}

// SetCredentialDeliverer wires the port that DeliverIfOwned uses to write credential material into a
// pod. It MUST be called before the provider is used concurrently (at construction/wiring time);
// New sets the real kube deliverer, tests/orchestrator a fake or the cloud-gcp-backed one. A nil
// argument is ignored (the fail-closed default is kept).
func (p *Provider) SetCredentialDeliverer(d CredentialDeliverer) {
	if d == nil {
		return
	}
	p.mu.Lock()
	p.deliverer = d
	p.mu.Unlock()
}

// randomID returns a generator of DNS-1123-label-safe handle IDs ("<prefix>-sb-<32 hex>"),
// unique per call via 128 bits of crypto/rand so a sandbox handle is NEVER reused across
// sessions, users, or personas — uniqueness is by construction, not by keying on a
// caller-supplied field a confused caller could repeat. 128 bits makes a birthday collision
// negligible even at extreme volume; freshID additionally rejects an in-use id.
func randomID(prefix string) func() (string, error) {
	return func() (string, error) {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("cloudgcp: generate sandbox id: %w", err)
		}
		return prefix + "-sb-" + hex.EncodeToString(b[:]), nil
	}
}

// freshID returns a handle ID not present in p.sandboxes (which retains DESTROYED entries too,
// so an id is never reused even after teardown — preventing a collision from reapplying egress
// to, or deleting the namespace of, an unrelated sandbox). The caller must hold p.mu.
func (p *Provider) freshID() (string, error) {
	for range 8 {
		id, err := p.newID()
		if err != nil {
			return "", err
		}
		if _, exists := p.sandboxes[id]; !exists {
			return id, nil
		}
	}
	return "", errors.New("cloudgcp: could not generate a unique sandbox id after 8 attempts")
}

// ProvisionSandbox creates a per-session, isolated, ephemeral sandbox enforcing spec's
// default-deny egress from the moment it exists.
func (p *Provider) ProvisionSandbox(ctx context.Context, spec interfaces.SandboxSpec) (interfaces.SandboxHandle, error) {
	// Ephemeral by default: refuse a non-positive lifetime rather than provision an unbounded
	// sandbox (a missing MaxTTL is a misconfiguration, not "lives forever").
	if spec.MaxTTL <= 0 {
		return interfaces.SandboxHandle{}, errors.New("cloudgcp: SandboxSpec.MaxTTL must be positive (ephemeral by default)")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate the handle under the lock and against the live+destroyed id set, so a (negligibly
	// unlikely) collision can never reapply egress to or tear down an existing sandbox.
	id, err := p.freshID()
	if err != nil {
		return interfaces.SandboxHandle{}, err
	}
	h := interfaces.SandboxHandle{ID: id}

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
		// Roll back on a DETACHED, bounded context. If Provision failed because the caller's ctx
		// was cancelled/expired, reusing it would make Clear fail immediately and orphan the
		// namespace (and any pod the API server accepted before kubectl was killed) — and the
		// handle is never returned, so this rollback is the only chance to reclaim it.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		if cerr := p.egress.Clear(cleanupCtx, h); cerr != nil {
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
	if sb.tainted {
		// A prior call could not guarantee this sandbox's perimeter; it is quarantined to teardown
		// only, so refuse any further egress change rather than operate on an unknown perimeter.
		return errors.New("cloudgcp: sandbox is tainted (its perimeter could not be guaranteed) — only teardown is permitted")
	}
	// Narrow-only: a permissive origin MUST NOT confer a stricter target's reach, so an update
	// may only REMOVE destinations, never add one beyond those already permitted. A widening
	// request cannot be honoured, so the sandbox fails CLOSED — its perimeter drops to deny-all
	// rather than keeping its prior (now-suspect) reach — and the call errors.
	//
	// CRITICAL (the in-memory egress is the source of truth for the narrow-only check, so it must
	// never claim a state the cloud is not actually in): sb.egress is updated ONLY to what was
	// CONFIRMED applied. If a Set fails, the cluster still holds the prior policy, so sb.egress is
	// left matching it and the error is surfaced — the caller MUST tear the sandbox down (a failed
	// egress change means the perimeter is no longer guaranteed). We never optimistically record
	// deny-all that did not actually take effect, which would otherwise leave a broader policy live
	// in the cluster while the provider believed it was denied.
	allowed := make(map[string]bool, len(sb.egress))
	for _, d := range sb.egress {
		allowed[d] = true
	}
	for _, d := range policy.Allowlist {
		if !allowed[d] {
			if err := p.egress.Set(ctx, h, nil); err != nil {
				// Could not even enforce deny-all: the perimeter is now unknown. Taint the sandbox
				// so only teardown is permitted, and surface the failure.
				sb.tainted = true
				return errors.Join(errWidenRefused, fmt.Errorf("cloudgcp: deny-all fallback failed, perimeter not guaranteed — destroy the sandbox: %w", err))
			}
			sb.egress = nil
			return errWidenRefused
		}
	}
	next := append([]string(nil), policy.Allowlist...)
	if err := p.egress.Set(ctx, h, next); err != nil {
		// The narrowed policy did not apply; fail closed to deny-all. Only claim deny-all if it
		// actually applied — otherwise leave sb.egress matching the cluster's still-live prior
		// policy, taint the sandbox (perimeter unknown → teardown only), and surface BOTH failures
		// (never swallow the fallback error).
		if derr := p.egress.Set(ctx, h, nil); derr != nil {
			sb.tainted = true
			return errors.Join(
				fmt.Errorf("cloudgcp: apply narrowed egress: %w", err),
				fmt.Errorf("cloudgcp: deny-all fallback also failed, perimeter not guaranteed — destroy the sandbox: %w", derr),
			)
		}
		sb.egress = nil
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
	// Best-effort shred of any injected credential before tearing the pod down. The AUTHORITATIVE
	// wipe is the pod deletion below (the credential lives in a medium: Memory volume that dies with
	// the pod), so a failure here — nothing was injected, or the exec is refused — is ignored; this
	// is defence in depth that shreds the secret a moment sooner.
	wipeCtx, wipeCancel := context.WithTimeout(ctx, deliverTimeout)
	_ = p.deliverer.Wipe(wipeCtx, h)
	wipeCancel()
	// Tear the workload down FIRST (stop the thing that could act), then clear its perimeter. A
	// runtime-destroy failure is fatal and is NOT marked dead — the sandbox may still be live, so
	// the caller (and a retry) must see it as live, exactly as the orchestrator's abort path
	// surfaces a failed destroy rather than assuming the sandbox is gone.
	if err := p.runtime.Destroy(ctx, h); err != nil {
		return fmt.Errorf("cloudgcp: destroy sandbox (may still be live): %w", err)
	}
	// The workload is gone; mark dead so any later operation fails closed. A Clear failure now
	// only leaves orphaned perimeter config (harmless — nothing routes through it), so it is
	// surfaced but does not resurrect the sandbox.
	sb.live = false
	sb.egress = nil
	// Clear on a DETACHED, bounded context — the same reasoning as the provision-rollback above:
	// runtime.Destroy may have waited out most of the caller's deadline, and once the sandbox is
	// committed dead there is no API path back to retry the perimeter cleanup (lookup rejects a
	// non-live handle), so the namespace would orphan until the reaper. Don't let a caller ctx that
	// expired during the pod-delete wait take the namespace cleanup down with it.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if err := p.egress.Clear(cleanupCtx, h); err != nil {
		return fmt.Errorf("cloudgcp: sandbox destroyed but clearing its perimeter failed: %w", err)
	}
	return nil
}

// RunTask runs the genuine engine inside the live sandbox h and returns the proposed commit. It
// gates the run on the sandbox being live and not tainted, then delegates the exec to the
// EngineRunner port.
//
// CONCURRENCY EXCEPTION: unlike every other method, RunTask does NOT hold p.mu across its port
// I/O. An engine run can take minutes; serialising it under p.mu (the package's default) would
// wedge every other sandbox's provision/apply/destroy for the whole run. So RunTask takes the lock
// only for the liveness/taint GATE, then releases it before the long runner.Run call. This is safe:
// DestroySandbox marks a sandbox dead UNDER the lock and tears the pod down, so a destroy racing an
// in-flight run either (a) is ordered before this gate — the gate then fails closed — or (b) lands
// after the gate, killing the pod mid-run, which surfaces as a runner error, never a task running
// in a torn-down (perimeter-gone) sandbox. The in-memory egress/liveness view is never mutated by
// RunTask, so releasing the lock cannot corrupt the narrow-only invariant the other methods rely on.
//
// LIFETIME: a sandbox can cross its MaxTTL expiry DURING the (post-gate) run; the provider does not
// re-check it mid-run. The run is bounded instead by task.Timeout (which the orchestrator caps to the
// time REMAINING to the session deadline) enforced in the runner, with the pod's activeDeadlineSeconds
// as the hard backstop — so the engine cannot outlive the sandbox even though this method's gate is
// point-in-time.
func (p *Provider) RunTask(ctx context.Context, h interfaces.SandboxHandle, task interfaces.EngineTask) (interfaces.EngineResult, error) {
	p.mu.Lock()
	sb, ok := p.lookup(h)
	if !ok || !sb.live {
		p.mu.Unlock()
		// Fail closed: a task must never run outside a live sandbox (unknown, destroyed, or expired).
		return interfaces.EngineResult{}, errors.New("cloudgcp: cannot run a task in an unknown, destroyed, or expired sandbox")
	}
	if sb.tainted {
		p.mu.Unlock()
		// A prior egress change could not guarantee this sandbox's perimeter; it is quarantined to
		// teardown only, so refuse to run the engine inside an unknown perimeter (tenet 3).
		return interfaces.EngineResult{}, errors.New("cloudgcp: sandbox is tainted (its perimeter could not be guaranteed) — only teardown is permitted")
	}
	p.mu.Unlock()
	return p.runner.Run(ctx, h, task)
}

// Owns reports whether h is a sandbox owned by EXACTLY this subject and session — the ownership
// oracle half of the data-plane Injector seam (providers/secrets-gcp Injector, which this Provider
// satisfies structurally). An unknown, destroyed, expired, or tainted sandbox, or a subject/session
// mismatch, is not owned (fail closed). This is the binding the provider attested at
// ProvisionSandbox (spec.Subject/SessionID -> handle), so an injection reaches only its owner's
// sandbox — no pooling (DESIGN.md §2.2; cloud.go SandboxSpec.Subject SECURITY).
func (p *Provider) Owns(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.owns(h, subject, session)
}

// owns is the lock-held ownership predicate shared by Owns and DeliverIfOwned. The caller holds p.mu.
func (p *Provider) owns(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID) bool {
	sb, ok := p.lookup(h)
	return ok && sb.live && !sb.tainted && sb.subject == subject && sb.session == session
}

// DeliverIfOwned atomically RE-CHECKS ownership under the lock and, only if it still holds, writes a
// copy of material into the owning sandbox's memory volume, returning whether it delivered. The
// single-step check-and-deliver closes the race where a teardown between a separate Owns and the
// write would let a credential land in a sandbox that is already gone. Any delivery error reports
// non-delivery (fail closed). The seam carries no context, so a bounded one is derived for the I/O.
func (p *Provider) DeliverIfOwned(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID, material []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.owns(h, subject, session) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()
	return p.deliverer.Deliver(ctx, h, material) == nil
}

// lookup returns the state for h, marking it dead first if it has aged past its MaxTTL so a
// caller sees an expired sandbox as not live (fail closed). The real workload also carries a
// hard activeDeadlineSeconds from MaxTTL, so the POD (and any injected credential material — the
// security-critical part) is reaped by Kubernetes at the deadline even if DestroySandbox is never
// called; this lazy check keeps the provider's own surface fail-closed in the interim.
//
// RESIDUAL (tracked): this in-memory reap does NOT itself delete the sandbox's NAMESPACE /
// NetworkPolicy / ConfigMap — only the pod self-terminates via activeDeadlineSeconds. If teardown
// is missed past the TTL those (now workload-free, credential-free) objects linger until swept.
// Sweeping them is a deploy/gcp/modules/gke responsibility (a reaper / namespace-TTL CronJob over
// console7-managed sandbox namespaces, PR-2b) — doing cloud I/O from inside this locked lookup
// path would be unsafe. The security guarantee (no lingering workload or credential) holds via the
// pod deadline; the residual is a resource-hygiene/quota concern, not an isolation one.
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
