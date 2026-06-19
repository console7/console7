package interfaces

import "time"

// This file declares the shared value types referenced by the provider contracts.
// They are intentionally thin: enough to give each interface method a real,
// typed signature, not a finished domain model. Fields and types will harden as
// the phases land (docs/ROADMAP.md); nothing here is an implementation.
//
// A deliberate invariant runs through these types: nothing that crosses a provider
// boundary carries plaintext long-lived credential material. Credentials are
// represented as opaque, short-lived references (see CredentialRef) so the type
// system itself discourages a control-plane component from holding a key at rest
// (DESIGN.md §8, GOAL.md tenet 4).

// Subject is an authenticated human principal — the adopter IdP's SSO/OIDC subject.
// It is the lineage anchor: every action traces back to a Subject through a
// per-session non-human identity (DESIGN.md §2.3).
type Subject string

// SessionID identifies one Console7 session. A session runs as exactly one persona
// with exactly one non-human identity, and is ephemeral by default.
type SessionID string

// Persona is the role a session runs as. There are deliberately only two, and there
// is deliberately no "actuate" persona — actuation is the pipeline's job under a
// human (DESIGN.md §1.2, GOAL.md tenet 6).
type Persona string

const (
	// PersonaAuthor develops: reads/edits within the target repo, runs its build
	// and test tooling, commits to a working branch, opens PRs. Holds NO production
	// credentials.
	PersonaAuthor Persona = "author"
	// PersonaOperate reads production telemetry (through the Observe Gateway) to
	// diagnose, and emits change only as a proposed artefact. Holds a READ-ONLY
	// production identity; cannot mutate.
	PersonaOperate Persona = "operate"
)

// Tier is the target artefact's criticality tier (T1 highest consequence … T4
// lowest). Rigour scales to tier; the objective is never waived, only its mechanism
// (GOAL.md tenet 8).
//
// WARNING: the underlying int values do NOT encode restrictiveness — Tier1 (most
// restrictive) is numerically less than Tier4 (least), and TierUnknown is zero.
// Callers MUST NOT compare Tiers as ints for take-the-max (DESIGN.md §4.2); doing so
// silently downgrades a mixed-tier session. Use MoreRestrictiveThan / MostRestrictive.
type Tier int

const (
	TierUnknown Tier = iota // fail-closed default: treat as the most restrictive.
	Tier1                   // highest consequence — human gate, full attestation.
	Tier2
	Tier3
	Tier4 // lowest consequence — highest volume.
)

// restrictiveness ranks a Tier so that a larger rank is MORE restrictive. Any
// unknown/unrecognised value ranks highest, so cross-tier resolution fails closed.
func (t Tier) restrictiveness() int {
	switch t {
	case Tier1:
		return 4
	case Tier2:
		return 3
	case Tier3:
		return 2
	case Tier4:
		return 1
	default: // TierUnknown and any out-of-range value.
		return 5
	}
}

// MoreRestrictiveThan reports whether t is strictly more restrictive than o. This is
// the only correct way to order Tiers; never compare the raw int values.
func (t Tier) MoreRestrictiveThan(o Tier) bool {
	return t.restrictiveness() > o.restrictiveness()
}

// MostRestrictive returns the most restrictive Tier among those given — the
// "take-the-max" reduction a cross-resource session binds to (DESIGN.md §4.2). With
// no arguments it returns TierUnknown, the fail-closed most-restrictive default; if
// any input is TierUnknown (an unresolved target), the result is TierUnknown.
func MostRestrictive(tiers ...Tier) Tier {
	if len(tiers) == 0 {
		return TierUnknown
	}
	winner := tiers[0]
	for _, t := range tiers[1:] {
		if t.MoreRestrictiveThan(winner) {
			winner = t
		}
	}
	return winner
}

// Stratum is the target artefact's authoring stratum (S1 Engineered … S5 Agentic).
type Stratum int

const (
	StratumUnknown Stratum = iota // fail-closed default.
	Stratum1                      // S1 Engineered.
	Stratum2
	Stratum3
	Stratum4
	Stratum5 // S5 Agentic.
)

// TierStratum is the authoritative criticality coordinate of a target, resolved
// from the policy system-of-record. Scope follows the artefact (GOAL.md tenet 4):
// session reach derives from the TARGET's TierStratum, never from who launched it
// and never from an in-repo file.
type TierStratum struct {
	Tier    Tier
	Stratum Stratum
}

// SessionProfile is the derived envelope a session runs inside: what it may reach
// and how far it may go. The PDP computes it from the target's TierStratum
// (DESIGN.md §1.3); the boundary (egress perimeter, IAM) enforces it.
type SessionProfile struct {
	Persona           Persona
	Target            TierStratum
	EgressAllowlist   []string      // default-deny: anything not listed is denied.
	AutonomyCeiling   string        // the session's maximum autonomy level.
	HumanGateRequired bool          // whether change requires a human gate to land.
	MaxTTL            time.Duration // hard lifetime; the session dies with it.
}

// RepoRef names a source repository at the adopter's SCM.
type RepoRef struct {
	Host  string // e.g. "github.com".
	Owner string
	Name  string
}

// ResourceRef names a non-repo target a session may touch (e.g. a production
// service whose telemetry the operate lane reads). Used for cross-tier reach
// resolution (DESIGN.md §4.2).
type ResourceRef struct {
	Kind string // e.g. "service", "dataset".
	ID   string
}

// CredentialRef is an OPAQUE, short-lived handle to credential material held in the
// adopter's secrets manager / key broker — never the material itself. A provider
// returns one of these so a control-plane component can refer to a credential
// (to inject it into a sandbox) WITHOUT ever holding the plaintext. Expiry is part
// of the type because ephemerality is a contract, not a convention (GOAL.md tenet 4).
type CredentialRef struct {
	// Ref is an indirection handle (e.g. a secrets-manager resource name or a
	// broker lease ID). It MUST NOT be, encode, or embed the secret value.
	Ref string
	// Expiry is when the referenced material stops being valid. A provider MUST set
	// it; a zero Expiry is invalid and MUST be treated as already-expired.
	Expiry time.Time
}

// Persona-scoped identity minted per session. It is the non-human identity (NHI)
// that the human Subject acts through; lineage is stamped Subject -> NHI -> action
// at the orchestrator (DESIGN.md §2.3).
type SessionIdentity struct {
	Subject   Subject
	SessionID SessionID
	Persona   Persona
	// Credential is an opaque reference to the short-lived cloud/SCM material this
	// identity carries. Never long-lived; never operator-readable.
	Credential CredentialRef
}
