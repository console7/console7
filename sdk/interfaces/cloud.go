package interfaces

import (
	"context"
	"time"
)

// SandboxSpec describes the isolated, ephemeral data-plane environment a session
// runs in. The egress policy is part of the spec because the perimeter is set at
// provision time, not negotiated with the workload afterwards.
type SandboxSpec struct {
	SessionID SessionID
	// Subject is the human principal the session acts for. The provider records the
	// (Subject, SessionID) -> SandboxHandle binding it attests to, so a later
	// subscription injection can be verified to reach only its owner's sandbox (no
	// pooling — DESIGN.md §2.2). It is identity to bind, never a credential: no secret
	// material crosses this seam.
	Subject Subject
	Persona Persona
	Egress  EgressPolicy
	// MaxTTL bounds the sandbox's lifetime; it is destroyed no later than this even
	// if teardown is not called (ephemeral by default — ARCHITECTURE.md §1).
	MaxTTL time.Duration
}

// EgressPolicy is a default-deny allowlist. The zero value (no entries) denies all
// egress; entries open only the specific destinations named. There is intentionally
// no "deny list" field — the model is allowlist-only so that "forgot to deny" can
// never silently permit (DESIGN.md §5.2).
type EgressPolicy struct {
	// Allowlist is the set of permitted destinations, composed from the inference
	// endpoint, approved registries/artefact chokepoint, approved internal services,
	// and approved MCP domains. Anything not listed is denied at the boundary.
	Allowlist []string
}

// SandboxHandle is an opaque reference to a provisioned sandbox.
type SandboxHandle struct {
	ID string
}

// CloudProvider abstracts sandbox isolation, networking, and the egress perimeter
// (ARCHITECTURE.md §5; default ref: GCP — gVisor + VPC firewall/NAT for the egress
// perimeter, with VPC Service Controls guarding the Google API surface only, not
// arbitrary egress). It is the seam behind which the authoritative, out-of-band
// boundary controls live.
type CloudProvider interface {
	// ProvisionSandbox creates a per-session, isolated, ephemeral sandbox enforcing
	// the spec's egress policy from the moment it exists.
	//
	// SECURITY: the implementation MUST enforce filesystem and process isolation at
	// the kernel/syscall boundary (gVisor / microVM), NEVER by asking the agent to
	// behave (DESIGN.md §5.1). It MUST apply the egress allowlist as default-deny at
	// the network perimeter BEFORE the workload can run, NEVER rely on the engine's
	// in-process proxy (DESIGN.md §5.2). It MUST NOT provision egress broader than
	// spec.Egress.Allowlist, MUST NOT reuse a sandbox across sessions, users, or
	// personas, and MUST NOT grant the sandbox any standing credential of its own.
	ProvisionSandbox(ctx context.Context, spec SandboxSpec) (SandboxHandle, error)

	// ApplyEgressPolicy narrows or sets the egress allowlist for a live sandbox —
	// e.g. when cross-repo reach forces take-the-max (DESIGN.md §4.2).
	//
	// SECURITY: the implementation MUST enforce the change at the out-of-band
	// perimeter, not inside the sandbox, and MUST fail closed (deny all) if the
	// policy cannot be applied. It MUST NEVER widen egress beyond what the session
	// profile permits, and a permissive origin MUST NOT confer a stricter target's
	// reach.
	ApplyEgressPolicy(ctx context.Context, h SandboxHandle, policy EgressPolicy) error

	// DestroySandbox tears the sandbox down and reclaims its resources.
	//
	// SECURITY: destruction MUST be irreversible and MUST wipe the ephemeral
	// workspace and any injected credential material; it MUST NOT snapshot, archive,
	// or otherwise persist sandbox contents anywhere the maintainer or another
	// session could read them (GOAL.md tenet 1, tenet 4).
	DestroySandbox(ctx context.Context, h SandboxHandle) error
}
