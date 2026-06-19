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
	// Fail closed on an unresolved target: TierUnknown/StratumUnknown is the most-
	// restrictive coordinate the SoR returns for something it does not recognise, and we
	// refuse to synthesise a permissive profile for it rather than guess a tier.
	if target.Tier == interfaces.TierUnknown || target.Stratum == interfaces.StratumUnknown {
		return interfaces.SessionProfile{}, fmt.Errorf("orchestrator: target %s/%s/%s did not resolve to a known tier × stratum (fail closed)", repo.Host, repo.Owner, repo.Name)
	}
	return interfaces.SessionProfile{
		Persona:         persona,
		Target:          target,
		EgressAllowlist: append([]string(nil), egressAllowlist...),
		// Phase-1 fixed; the real autonomy-ceiling matrix is Phase 3.
		AutonomyCeiling: "supervised",
		// A target more restrictive than T3 owes the human gate; the T3 lane does not
		// (docs/ROADMAP.md Phase 1). Compared via the restrictiveness ordering, never the
		// raw Tier int (interfaces.Tier doc).
		HumanGateRequired: target.Tier.MoreRestrictiveThan(interfaces.Tier3),
		MaxTTL:            maxTTL,
	}, nil
}
