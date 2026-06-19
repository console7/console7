package devkit

import (
	"context"
	"testing"

	"github.com/console7/console7/sdk/interfaces"
)

func TestFixedPolicySoR_ResolveRepo_KnownIsT3UnknownFailsClosed(t *testing.T) {
	known := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"}
	sor := NewFixedPolicySoR(known)
	ctx := context.Background()

	ts, err := sor.ResolveRepo(ctx, known)
	if err != nil {
		t.Fatalf("resolve known: %v", err)
	}
	if ts.Tier != interfaces.Tier3 || ts.Stratum != interfaces.Stratum1 {
		t.Errorf("known repo resolved to %v, want Tier3/Stratum1", ts)
	}

	unknown := interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "other"}
	ts, err = sor.ResolveRepo(ctx, unknown)
	if err != nil {
		t.Fatalf("resolve unknown: %v", err)
	}
	// Fail closed: an unknown target is the most restrictive coordinate, never permissive.
	if ts.Tier != interfaces.TierUnknown || ts.Stratum != interfaces.StratumUnknown {
		t.Errorf("unknown repo resolved to %v, want TierUnknown/StratumUnknown (fail closed)", ts)
	}
	if interfaces.Tier1.MoreRestrictiveThan(ts.Tier) {
		t.Errorf("unknown repo resolved to a permissive tier %d", ts.Tier)
	}
}

func TestFixedPolicySoR_ResolveResource_KnownAndFailClosed(t *testing.T) {
	res := interfaces.ResourceRef{Kind: "service", ID: "checkout"}
	sor := NewFixedPolicySoR().AllowResource(res)
	ctx := context.Background()

	ts, err := sor.ResolveResource(ctx, res)
	if err != nil {
		t.Fatalf("resolve known resource: %v", err)
	}
	if ts.Tier != interfaces.Tier3 || ts.Stratum != interfaces.Stratum1 {
		t.Errorf("known resource resolved to %v, want Tier3/Stratum1", ts)
	}

	ts, err = sor.ResolveResource(ctx, interfaces.ResourceRef{Kind: "service", ID: "unknown"})
	if err != nil {
		t.Fatalf("resolve unknown resource: %v", err)
	}
	if ts.Tier != interfaces.TierUnknown {
		t.Errorf("unknown resource resolved to %v, want fail-closed TierUnknown", ts)
	}
}
