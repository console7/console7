package devkit

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// SandboxRegistry is an in-memory stand-in for the (not-yet-built) data-plane sandbox
// a credential is injected into. In production the binding between a SandboxHandle and
// the session/subject that owns it is attested by the CloudProvider; here it is an
// in-process map.
//
// It is the ownership oracle MemSecrets.InjectSubscriptionToken needs: SandboxHandle is
// an opaque {ID string}, so the SecretsProvider cannot, from the handle alone, tell
// whether a sandbox belongs to the injecting subject's session. The registry answers
// that question (Owns) and is the only place delivered plaintext material lands
// (deliver / Injected), so a test can prove a token reached its OWNER's sandbox and
// nowhere else.
//
// SECURITY (Phase-1 spec note): the handle here is a bare random string and the
// ownership check is a map lookup. A production SandboxHandle likely needs a verifiable
// (signed) session binding so a forged or stale handle cannot be presented to the
// SecretsProvider. Flagged in docs/THREAT-MODEL.md §1; do not rely on this model.
type SandboxRegistry struct {
	mu       sync.Mutex
	bound    map[string]binding // handle ID -> owning subject/session
	injected map[string][]byte  // handle ID -> material delivered to that sandbox
}

type binding struct {
	subject interfaces.Subject
	session interfaces.SessionID
	// expiry bounds the binding's life. A zero value never expires; otherwise ownership
	// (and thus injection) fails closed once the wall clock passes it, so a token cannot be
	// injected into a sandbox the CloudProvider considers gone past its MaxTTL.
	expiry time.Time
}

// live reports whether the binding is still within its (optional) expiry.
func (b binding) live() bool {
	return b.expiry.IsZero() || time.Now().Before(b.expiry)
}

// NewSandboxRegistry returns an empty registry.
func NewSandboxRegistry() *SandboxRegistry {
	return &SandboxRegistry{
		bound:    make(map[string]binding),
		injected: make(map[string][]byte),
	}
}

// Provision registers a fresh, non-expiring sandbox owned by (subject, session) and returns
// its handle. It models the CloudProvider provisioning a per-session sandbox; here it only
// records the ownership binding the SecretsProvider will later check.
func (r *SandboxRegistry) Provision(subject interfaces.Subject, session interfaces.SessionID) interfaces.SandboxHandle {
	return r.ProvisionWithExpiry(subject, session, time.Time{})
}

// ProvisionWithExpiry is Provision with a hard ownership expiry: past expiry the binding is
// no longer owned, so injection into it fails closed (the lazy equivalent of the sandbox
// being reaped at its MaxTTL). A zero expiry never expires.
func (r *SandboxRegistry) ProvisionWithExpiry(subject interfaces.Subject, session interfaces.SessionID, expiry time.Time) interfaces.SandboxHandle {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := "sbx-" + randHex(8)
	r.bound[id] = binding{subject: subject, session: session, expiry: expiry}
	return interfaces.SandboxHandle{ID: id}
}

// Owns reports whether h is a known, unexpired sandbox owned by exactly this subject and
// session. An unknown, mismatched, or expired handle is not owned (fail closed).
func (r *SandboxRegistry) Owns(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bound[h.ID]
	return ok && b.subject == subject && b.session == session && b.live()
}

// Destroy removes a sandbox's ownership binding and wipes any material injected into it.
// It models the CloudProvider tearing the sandbox down: afterwards the handle is unknown,
// so Owns fails closed and Injected reports nothing — there is no path back. Destroying an
// unknown handle is a no-op (idempotent at the registry; MemCloud is the one that fails
// closed on a double destroy).
func (r *SandboxRegistry) Destroy(h interfaces.SandboxHandle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.bound, h.ID)
	delete(r.injected, h.ID)
}

// DeliverIfOwned atomically re-checks ownership and, only if it still holds, places a copy
// of material into the sandbox's injected slot — returning whether it delivered. Doing the
// ownership check and the delivery under a SINGLE lock closes the race where a Destroy
// between a separate Owns and deliver would let material land in a just-destroyed sandbox.
// Only a SecretsProvider in this package calls it, and only after its own attended /
// single-beneficiary checks pass. A copy is stored so the caller's transient plaintext can
// be zeroed independently.
func (r *SandboxRegistry) DeliverIfOwned(h interfaces.SandboxHandle, subject interfaces.Subject, session interfaces.SessionID, material []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.bound[h.ID]
	if !ok || b.subject != subject || b.session != session || !b.live() {
		return false
	}
	cp := make([]byte, len(material))
	copy(cp, material)
	r.injected[h.ID] = cp
	return true
}

// Injected returns the material delivered to a sandbox, if any. It is a test-only
// inspection hook — it lets a bench assert a token landed in the OWNER's sandbox (and,
// by checking every other handle, nowhere else). It is deliberately the ONLY read path
// for injected material; there is no read path on the SecretsProvider itself.
//
// It enforces expiry on this READ path: an expired sandbox's material is unreachable
// (and lazily wiped) here regardless of whether any CloudProvider method has run, so a
// token cannot be read past the sandbox's MaxTTL even without an explicit teardown — the
// registry's Owns / DeliverIfOwned / Injected paths are all fail-closed past expiry.
func (r *SandboxRegistry) Injected(h interfaces.SandboxHandle) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, bound := r.bound[h.ID]; !bound || !b.live() {
		// Unknown or expired binding: wipe any lingering material and report nothing.
		delete(r.injected, h.ID)
		return nil, false
	}
	m, ok := r.injected[h.ID]
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(m))
	copy(cp, m)
	return cp, true
}

// randHex returns n cryptographically-random bytes hex-encoded. It panics on the
// (practically impossible) failure of the system CSPRNG rather than returning a
// predictable value — a predictable handle/ref would be a security defect.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("devkit: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
