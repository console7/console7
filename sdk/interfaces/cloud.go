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

// EngineTask is one governed unit of work the orchestrator asks the sandbox to run through the
// genuine Claude Code engine (DESIGN.md §1.4 — Console7 wraps the engine, it does NOT reimplement
// the agent). It carries only what the engine needs to PROPOSE a change; it is never a credential
// carrier — no token or subscription material crosses this seam, that is injected separately and
// by reference via the SecretsProvider/keybroker, exactly like SandboxSpec.Subject.
type EngineTask struct {
	// SessionID identifies the session whose sandbox runs this task; it is the lineage anchor the
	// orchestrator stamps the resulting commit and evidence against.
	SessionID SessionID
	// Profile is the resolved session envelope. The implementation MUST render it into the engine's
	// LOCKED managed-settings INSIDE the sandbox BEFORE the engine starts — the agent never applies
	// or overrides its own policy (DESIGN.md §5.1; tenet 3 — in-band guards are defence-in-depth,
	// the locked settings ride on top of the boundary). Profile.Persona selects the author/operate
	// permission + hook set.
	Profile SessionProfile
	// Repo and Branch are the working coordinates: the engine works the checked-out repo and commits
	// onto Branch. Branch MUST NOT be a protected/default branch — the session proposes, never
	// actuates onto a protected ref (tenet 6).
	Repo   RepoRef
	Branch string
	// Prompt is the task instruction handed to the headless engine (`claude -p`). It is UNTRUSTED
	// content (it may originate from an issue/PR body) and MUST influence only the engine's work —
	// never the egress perimeter, the isolation boundary, or the engine's own locked policy, all of
	// which are enforced out-of-band regardless of what the prompt says (tenet 3).
	Prompt string
	// Timeout bounds the engine run. The implementation MUST cap it to the sandbox's remaining
	// lifetime and MUST NOT let a run outlive the session deadline (ephemeral by default; tenet 5).
	Timeout time.Duration
}

// EngineResult is what a completed engine run yields back to the control plane: the PROPOSAL the
// orchestrator signs and opens as a PR. The engine itself actuates nothing (tenet 6).
type EngineResult struct {
	// CommitDigest is the digest of the REAL commit the engine produced on the working branch — the
	// bytes the orchestrator hands to the key broker to be signed by the session NHI (DESIGN.md
	// §2.3: produced artefacts are cryptographically signed by the session identity). It MUST be
	// non-empty when Changed is true; a run that produced no commit MUST set Changed false rather
	// than return a zero digest the orchestrator would sign as if work had happened.
	CommitDigest []byte
	// HeadSHA is the engine-produced commit's object id on the working branch. It is the head a
	// later (Tier-2) control-plane-side push + PR consumes; this seam never pushes to a remote.
	HeadSHA string
	// FilesChanged is a short, human-auditable summary of the proposed change (paths / counts) for
	// the PR body and the evidence record. It MUST NOT carry secret material or file CONTENTS — it
	// is a summary for an auditor, never a data-exfiltration channel out of the sandbox (tenet 1).
	FilesChanged []string
	// Changed reports whether the run produced any commit. A no-op (Changed false) is a legitimate
	// outcome the orchestrator records as "no change proposed" rather than signing an empty digest.
	Changed bool
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
	// session could read them (GOAL.md tenet 1, tenet 5).
	DestroySandbox(ctx context.Context, h SandboxHandle) error

	// RunTask runs the genuine Claude Code engine for one governed task INSIDE the live sandbox
	// identified by h, and returns the proposed change as an EngineResult. It is the "do the work"
	// step the orchestrator calls between narrowing egress and signing/opening the PR, so the engine
	// always runs under the already-narrowed, default-deny perimeter.
	//
	// SECURITY: the implementation MUST run the engine ONLY inside the existing sandbox h (never
	// spawn a fresh or shared one) and MUST fail closed if h is unknown, already destroyed, expired,
	// or tainted — a task MUST NEVER run outside a live, perimeter-intact sandbox. It MUST render
	// task.Profile into the engine's LOCKED managed-settings inside the sandbox BEFORE the engine
	// starts, and MUST NOT let the agent self-apply or override that policy (DESIGN.md §5.1; tenet
	// 3). It MUST NOT widen the sandbox's egress to run the task (tenet 3), and MUST NOT let the
	// engine actuate the change — no push to a protected branch, no merge, no deploy: the engine
	// PROPOSES a commit on the working branch and the control plane opens the PR (tenet 6; DESIGN.md
	// §1.2). It MUST NOT return secret material, engine transcripts, or full sandbox contents — only
	// the digest/head/summary the control plane needs to attest and propose (tenet 1). It MUST
	// honour task.Timeout and MUST NOT let the run outlive the sandbox's hard lifetime (tenet 5).
	// The returned CommitDigest is the bytes the session NHI signs (the orchestrator signs the
	// engine's real output, never a synthesised stand-in — DESIGN.md §2.3, tenet 7).
	RunTask(ctx context.Context, h SandboxHandle, task EngineTask) (EngineResult, error)
}
