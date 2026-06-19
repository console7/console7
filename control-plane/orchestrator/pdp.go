package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// ResolveProfile is the Phase-1 minimal Policy Decision Point: it resolves the TARGET's
// tier × stratum through the authoritative PolicySoR seam — never from an in-repo file
// (tenet 3) — and derives the SessionProfile the session runs inside. The full tier ×
// stratum → profile policy (autonomy-ceiling and human-gate matrices, composed egress
// from approved registries/MCP) is Phase 3 (docs/ROADMAP.md); here the mapping is the
// fixed single-lane envelope.
//
// It fails closed: if the SoR cannot resolve the target to a known tier × stratum, no
// profile is produced and the session MUST NOT launch. egressAllowlist seeds the profile's
// default-deny perimeter (at minimum the lane's inference endpoints); maxTTL is the hard
// session lifetime.
func ResolveProfile(ctx context.Context, sor interfaces.PolicySoR, repo interfaces.RepoRef, persona interfaces.Persona, egressAllowlist []string, maxTTL time.Duration) (interfaces.SessionProfile, error) {
	if sor == nil {
		return interfaces.SessionProfile{}, errors.New("orchestrator: nil PolicySoR")
	}
	target, err := sor.ResolveRepo(ctx, repo)
	if err != nil {
		return interfaces.SessionProfile{}, err
	}
	// Fail closed on anything outside the single Phase-1 lane. Phase 1 supports EXACTLY
	// author × Tier-3 × Stratum-1; the full tier × stratum → profile matrix (autonomy
	// ceilings, the human-gate enforcement, composed egress) is Phase 3. So a target that
	// resolves to any OTHER coordinate — a known-but-unsupported Tier1/Stratum5 as much as an
	// unknown or out-of-range one — is refused rather than run under a single-lane envelope it
	// was not sized for (it would otherwise inherit T3's egress/TTL and an unenforced
	// human-gate flag).
	if target.Tier != interfaces.Tier3 || target.Stratum != interfaces.Stratum1 {
		return interfaces.SessionProfile{}, fmt.Errorf("orchestrator: target %s/%s/%s resolved to tier %d × stratum %d, outside the supported Phase-1 author × T3/S1 lane (fail closed)", repo.Host, repo.Owner, repo.Name, target.Tier, target.Stratum)
	}
	return interfaces.SessionProfile{
		Persona:         persona,
		Target:          target,
		EgressAllowlist: append([]string(nil), egressAllowlist...),
		// Phase-1 fixed; the real autonomy-ceiling matrix is Phase 3.
		AutonomyCeiling: "supervised",
		// The single Phase-1 lane is T3, which does not owe the human gate (docs/ROADMAP.md
		// Phase 1); the guard above already rejected any more-restrictive target. The
		// tier × stratum → gate matrix is Phase 3.
		HumanGateRequired: false,
		MaxTTL:            maxTTL,
	}, nil
}
