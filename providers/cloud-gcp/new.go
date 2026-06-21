package cloudgcp

import (
	"context"
	"fmt"
	"os"
)

// New constructs the production Provider, wired to the real kubectl/gcloud adapters
// (kube_exec.go). It fetches cluster credentials into a private kubeconfig via
// `gcloud container clusters get-credentials` (using the adopter's ambient Workload-Identity
// context — no key file, no stored secret), so the provider holds no standing credential.
//
// The adapters shell out to the adopter's pinned `kubectl` + `gcloud` — the deliberate
// zero-dependency choice (Option A, PR-2a): this Tier-1 public module gains no new
// dependency, and a deployment wanting a typed Kubernetes client swaps the adapters via
// NewWithPorts without touching the CloudProvider seam.
//
// Call Close at shutdown to remove the private kubeconfig.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}

	// A private kubeconfig so the provider never mutates the operator's ambient ~/.kube/config,
	// and so a sandbox process cannot read a cluster credential from a well-known path.
	kubeconfig, err := os.CreateTemp("", "cloudgcp-kubeconfig-*")
	if err != nil {
		return nil, fmt.Errorf("cloudgcp: create private kubeconfig: %w", err)
	}
	kubeconfigPath := kubeconfig.Name()
	// Close the handle; the path is what the adapters pass to kubectl/gcloud via KUBECONFIG.
	if cerr := kubeconfig.Close(); cerr != nil {
		_ = os.Remove(kubeconfigPath)
		return nil, fmt.Errorf("cloudgcp: close private kubeconfig: %w", cerr)
	}

	rc := &kubeRunner{kubeconfig: kubeconfigPath, project: cfg.ProjectID}
	if err := rc.getCredentials(ctx, cfg.Cluster, cfg.Location); err != nil {
		_ = os.Remove(kubeconfigPath)
		return nil, err
	}
	// Fail closed at construction if the cluster would not actually ENFORCE the egress
	// NetworkPolicy (no GKE Dataplane V2 / network-policy addon) — otherwise the perimeter would be
	// silently inert and ProvisionSandbox would run a workload it believes is isolated.
	if err := rc.preflightNetworkPolicyEnforced(ctx, cfg.Cluster, cfg.Location); err != nil {
		_ = os.Remove(kubeconfigPath)
		return nil, err
	}

	p, err := NewWithPorts(
		&kubeRuntime{run: rc, cfg: cfg},
		&netpolEgressController{run: rc, cfg: cfg},
		cfg.NamePrefix,
		nil,
	)
	if err != nil {
		_ = os.Remove(kubeconfigPath)
		return nil, err
	}
	p.kubeconfigPath = kubeconfigPath
	return p, nil
}

// Close releases the provider's private kubeconfig. It is safe to call on a Provider built by
// NewWithPorts (no kubeconfig), where it is a no-op.
func (p *Provider) Close() error {
	if p.kubeconfigPath == "" {
		return nil
	}
	err := os.Remove(p.kubeconfigPath)
	p.kubeconfigPath = ""
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cloudgcp: remove private kubeconfig: %w", err)
	}
	return nil
}
