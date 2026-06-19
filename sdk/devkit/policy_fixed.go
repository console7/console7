package devkit

import (
	"context"

	"github.com/console7/console7/sdk/interfaces"
)

// fixedTarget is the Phase-1 single-lane scope: Tier-3 Standard × Stratum-1 Engineered —
// highest-volume, lowest-consequence, the lane that proves the pattern without owing the
// T1 human gate (docs/ROADMAP.md Phase 1).
var fixedTarget = interfaces.TierStratum{Tier: interfaces.Tier3, Stratum: interfaces.Stratum1}

// FixedPolicySoR is an in-memory stand-in for a PolicySoR (interfaces.PolicySoR) that
// resolves a fixed, known set of targets to Tier-3 × Stratum-1 and fails closed — to the
// MOST restrictive tier × stratum — for everything else. It models the Phase-1 single-lane
// scope where the tier × stratum is fixed rather than looked up from a live GRC registry;
// the registry-backed adapter is Phase 3 (docs/ROADMAP.md).
//
// It upholds the two load-bearing PolicySoR invariants on a bench: the result comes from
// this central record (never from an in-repo file the governed agent could edit), and an
// unknown target resolves to TierUnknown/StratumUnknown — the most restrictive coordinate
// by construction (interfaces.Tier.restrictiveness ranks unknown highest) — never a
// permissive default.
type FixedPolicySoR struct {
	repos     map[interfaces.RepoRef]bool
	resources map[interfaces.ResourceRef]bool
}

// NewFixedPolicySoR returns a PolicySoR that recognises the given repos (each resolving to
// Tier-3 × Stratum-1) and fails closed on everything else.
func NewFixedPolicySoR(knownRepos ...interfaces.RepoRef) *FixedPolicySoR {
	repos := make(map[interfaces.RepoRef]bool, len(knownRepos))
	for _, r := range knownRepos {
		repos[r] = true
	}
	return &FixedPolicySoR{repos: repos, resources: make(map[interfaces.ResourceRef]bool)}
}

// AllowResource registers a non-repo target as known (resolving to Tier-3 × Stratum-1) and
// returns the receiver for chaining. The single-lane spine uses ResolveRepo; the resource
// path upholds the same fail-closed contract for the conformance suite and later
// cross-tier reach.
func (p *FixedPolicySoR) AllowResource(res interfaces.ResourceRef) *FixedPolicySoR {
	p.resources[res] = true
	return p
}

// ResolveRepo returns the authoritative TierStratum for a repository.
func (p *FixedPolicySoR) ResolveRepo(ctx context.Context, repo interfaces.RepoRef) (interfaces.TierStratum, error) {
	if p.repos[repo] {
		return fixedTarget, nil
	}
	return mostRestrictive, nil
}

// ResolveResource returns the authoritative TierStratum for a non-repo resource.
func (p *FixedPolicySoR) ResolveResource(ctx context.Context, res interfaces.ResourceRef) (interfaces.TierStratum, error) {
	if p.resources[res] {
		return fixedTarget, nil
	}
	return mostRestrictive, nil
}

// mostRestrictive is the fail-closed coordinate for an unrecognised target: the zero
// value, which TierUnknown/StratumUnknown make the most restrictive (never permissive).
var mostRestrictive = interfaces.TierStratum{Tier: interfaces.TierUnknown, Stratum: interfaces.StratumUnknown}
