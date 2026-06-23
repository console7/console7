package devkit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// MemCloud is an in-memory stand-in for a CloudProvider (interfaces.CloudProvider). It
// models the control-plane-observable lifecycle of a sandbox — provisioned with a
// default-deny egress allowlist, that allowlist narrowable (never wideable) while live,
// then irreversibly destroyed — so the orchestration spine and the conformance suite can
// exercise the CloudProvider contract on a bench.
//
// It is backed by a SandboxRegistry: ProvisionSandbox mints the handle and records the
// (subject, session) ownership binding there, so the SAME registry a MemSecrets checks
// before injecting a subscription token already knows the sandbox MemCloud provisioned.
// DestroySandbox wipes that binding and any injected material through the registry.
//
// SCOPE: MemCloud asserts the BEHAVIOURAL invariants the interface promises (a fresh
// handle per session, egress recorded as default-deny, narrow-only updates, irreversible
// destroy that wipes injected material, no operation on an unknown/destroyed handle). It
// does NOT provide the authoritative guarantees a real provider must — gVisor/microVM
// syscall isolation and an out-of-band VPC egress perimeter. Those land with
// providers/cloud-gcp + sandbox/ in a later, boundary-first Phase-1 PR (docs/ROADMAP.md).
// Do not mistake a green run here for a real perimeter. MaxTTL expiry is enforced on
// MemCloud's own surface (Live/ApplyEgressPolicy/EgressOf/DestroySandbox fail closed once a
// sandbox is past its TTL); the shared SandboxRegistry ownership oracle does not itself
// expire — a real provider reaps the sandbox and its attestation, and the broker already
// caps every minted credential to the session deadline.
type MemCloud struct {
	mu        sync.Mutex
	reg       *SandboxRegistry
	sandboxes map[string]*memSandbox
	lastTask  interfaces.EngineTask // the most recent RunTask input, for test assertions.
}

// memSandbox is the lifecycle state MemCloud tracks for one provisioned sandbox; the
// ownership binding and any injected material live in the shared SandboxRegistry.
type memSandbox struct {
	session interfaces.SessionID
	persona interfaces.Persona
	egress  []string // the default-deny allowlist currently in force.
	expiry  time.Time
	live    bool
}

// reapIfExpired tears down a sandbox that has aged past its MaxTTL: it marks it dead, drops
// its egress, and clears the shared registry's ownership binding + injected material — the
// lazy equivalent of a background reaper, so an expired sandbox can be neither operated on
// nor injected into, and its material does not linger. The caller must hold c.mu.
func (c *MemCloud) reapIfExpired(h interfaces.SandboxHandle, sb *memSandbox) {
	if sb.live && !time.Now().Before(sb.expiry) {
		sb.live = false
		sb.egress = nil
		c.reg.Destroy(h)
	}
}

// lookup returns the sandbox for h, reaping it first if it has expired, so callers see an
// expired sandbox as not live. The caller must hold c.mu.
func (c *MemCloud) lookup(h interfaces.SandboxHandle) (*memSandbox, bool) {
	sb, ok := c.sandboxes[h.ID]
	if !ok {
		return nil, false
	}
	c.reapIfExpired(h, sb)
	return sb, true
}

// NewMemCloud returns a MemCloud backed by reg. The registry is shared with the
// SecretsProvider so a provisioned sandbox is a known, owned injection target.
func NewMemCloud(reg *SandboxRegistry) *MemCloud {
	return &MemCloud{reg: reg, sandboxes: make(map[string]*memSandbox)}
}

// ProvisionSandbox mints a fresh, owned sandbox enforcing spec's default-deny egress.
func (c *MemCloud) ProvisionSandbox(ctx context.Context, spec interfaces.SandboxSpec) (interfaces.SandboxHandle, error) {
	// Ephemeral by default: a sandbox with no positive lifetime is a misconfiguration,
	// not one that lives forever. Refuse it rather than provision an unbounded sandbox.
	if spec.MaxTTL <= 0 {
		return interfaces.SandboxHandle{}, errors.New("devkit: MemCloud requires a positive SandboxSpec.MaxTTL (ephemeral by default)")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The registry mints the handle and records the (subject, session) ownership binding
	// the SecretsProvider later checks — modelling the production attestation that the
	// CloudProvider vouches for a sandbox's owner. A fresh handle per call means a sandbox
	// is NEVER reused across sessions, users, or personas.
	expiry := time.Now().Add(spec.MaxTTL)
	// Record the same expiry in the registry binding so ownership (and thus injection) also
	// fails closed past the TTL, not just MemCloud's own surface.
	h := c.reg.ProvisionWithExpiry(spec.Subject, spec.SessionID, expiry)
	c.sandboxes[h.ID] = &memSandbox{
		session: spec.SessionID,
		persona: spec.Persona,
		egress:  append([]string(nil), spec.Egress.Allowlist...),
		expiry:  expiry,
		live:    true,
	}
	return h, nil
}

// ApplyEgressPolicy narrows the egress allowlist for a live sandbox.
func (c *MemCloud) ApplyEgressPolicy(ctx context.Context, h interfaces.SandboxHandle, policy interfaces.EgressPolicy) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	sb, ok := c.lookup(h)
	if !ok || !sb.live {
		// Fail closed: an unknown, destroyed, or expired sandbox has no perimeter to narrow.
		return errors.New("devkit: MemCloud cannot apply egress to an unknown, destroyed, or expired sandbox")
	}
	// Narrow-only: a permissive origin MUST NOT confer a stricter target's reach, so an
	// update may only remove destinations, never add one beyond those already permitted
	// (take-the-max narrows; it never widens). A widening policy cannot be applied, so the
	// sandbox fails CLOSED — its egress drops to deny-all rather than retaining its prior
	// (now suspect) reach — and the call errors.
	allowed := make(map[string]bool, len(sb.egress))
	for _, d := range sb.egress {
		allowed[d] = true
	}
	for _, d := range policy.Allowlist {
		if !allowed[d] {
			sb.egress = nil
			return errors.New("devkit: MemCloud refuses to widen egress beyond the provisioned allowlist; egress denied")
		}
	}
	sb.egress = append([]string(nil), policy.Allowlist...)
	return nil
}

// DestroySandbox irreversibly tears the sandbox down and wipes any injected material.
func (c *MemCloud) DestroySandbox(ctx context.Context, h interfaces.SandboxHandle) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	sb, ok := c.lookup(h)
	if !ok || !sb.live {
		// Destroying an unknown, already-destroyed, or expired sandbox fails closed — the
		// caller's view of what exists is wrong, and silently succeeding would mask it.
		// (An expired sandbox was already reaped — its material wiped — by lookup.)
		return errors.New("devkit: MemCloud cannot destroy an unknown, already-destroyed, or expired sandbox")
	}
	// Irreversible: drop the egress, mark dead, and wipe the registry's ownership binding
	// and injected credential material. There is no snapshot/archive path, and a later
	// operation on the handle fails closed above.
	sb.live = false
	sb.egress = nil
	c.reg.Destroy(h)
	return nil
}

// RunTask is the bench stand-in for the genuine engine run. It does NOT launch claude (the
// bench has no engine, no credential, and must stay offline and reproducible): it derives a
// DETERMINISTIC digest over the task coordinates so the orchestration spine signs a real-shaped
// digest end to end, exactly the role the orchestrator's old synthetic commitDigest played before
// the seam existed. A real CloudProvider (providers/cloud-gcp, console7-cloud-local) runs the
// engine and returns the genuine commit; MemCloud models only the lifecycle and the seam shape.
//
// It fails closed on an unknown, destroyed, or expired sandbox — a task must never "run" outside a
// live sandbox, the same gate ApplyEgressPolicy/DestroySandbox enforce — so the conformance
// no-run-after-destroy invariant holds against the double too.
func (c *MemCloud) RunTask(ctx context.Context, h interfaces.SandboxHandle, task interfaces.EngineTask) (interfaces.EngineResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sb, ok := c.lookup(h)
	if !ok || !sb.live {
		return interfaces.EngineResult{}, errors.New("devkit: MemCloud cannot run a task in an unknown, destroyed, or expired sandbox")
	}
	c.lastTask = task // record the input so a test can assert the orchestrator threaded the right lane/env.
	digest := benchCommitDigest(task)
	return interfaces.EngineResult{
		CommitDigest: digest,
		HeadSHA:      hex.EncodeToString(digest)[:40],
		FilesChanged: []string{"(devkit MemCloud stand-in: no genuine engine run, deterministic digest over task coordinates)"},
		Changed:      true,
	}, nil
}

// LastTask returns the most recent EngineTask passed to RunTask, a test-only inspection hook so a
// test can assert the orchestrator threaded the right inference lane/env into the engine invocation.
func (c *MemCloud) LastTask() interfaces.EngineTask {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastTask
}

// benchCommitDigest derives the deterministic digest MemCloud.RunTask "produces". It is the
// relocated body of the orchestrator's former synthetic commitDigest: a SHA-256 over the work's
// coordinates, domain-tagged "c7-commit-v1" so a commit signature can never be confused with an
// evidence-record signature minted by the same NHI key (cf. the orchestrator's evidenceDomain).
func benchCommitDigest(task interfaces.EngineTask) []byte {
	h := sha256.New()
	h.Write([]byte("c7-commit-v1"))
	for _, s := range []string{task.Repo.Host, task.Repo.Owner, task.Repo.Name, task.Branch, string(task.SessionID)} {
		var u8 [8]byte
		binary.BigEndian.PutUint64(u8[:], uint64(len(s)))
		h.Write(u8[:])
		h.Write([]byte(s))
	}
	return h.Sum(nil)
}

// Live reports whether h is a known, not-yet-destroyed, not-yet-expired sandbox. Test-only
// inspection hook.
func (c *MemCloud) Live(h interfaces.SandboxHandle) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	sb, ok := c.lookup(h)
	return ok && sb.live
}

// EgressOf returns the egress allowlist currently in force for an operable sandbox. Test-only.
func (c *MemCloud) EgressOf(h interfaces.SandboxHandle) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sb, ok := c.lookup(h)
	if !ok || !sb.live {
		return nil, false
	}
	return append([]string(nil), sb.egress...), true
}
