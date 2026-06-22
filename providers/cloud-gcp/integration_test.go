//go:build cloud_gcp_integration

// Opt-in live integration test against a real GKE cluster (e.g. one stood up by
// deploy/gcp/modules/gke in console7-dev). It is NEVER part of the CI gate — it compiles only
// under `-tags cloud_gcp_integration` and skips unless the environment names a project,
// location, and cluster. It exercises the REAL kubectl/gcloud adapter: provision a sandbox
// namespace + gVisor pod, narrow its egress, and tear it down.
//
// Run:
//
//	C7_GKE_PROJECT=console7-dev \
//	C7_GKE_LOCATION=us-east4 \
//	C7_GKE_CLUSTER=console7-sandbox \
//	go test -tags cloud_gcp_integration -run TestIntegration ./providers/cloud-gcp/...
//
// Requires `kubectl` + `gcloud` on PATH and ambient credentials (gcloud ADC / Workload Identity).
//
// NOTE: the authoritative egress + metadata-block ASSERTIONS (a non-allowlisted host and every
// metadata endpoint are unreachable from inside the sandbox) need both modules/gke (PR-2b) and the
// signed sandbox image (now wired — Config.SandboxImage, B3). RunTask (the genuine `claude -p` run)
// is still NOT called below: it additionally needs the run-time credential injection (B5/B9) and the
// managed-settings render+mount (B4), so until those land the seam's logic is proven by the in-memory
// InMemoryEngineRunner conformance + white-box tests (Tier-2 residual, see kube_exec.go). The B11
// extensions add the through-the-proxy egress/metadata assertions and the genuine RunTask run.
package cloudgcp

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

func TestIntegration_ProvisionNarrowDestroy(t *testing.T) {
	project := os.Getenv("C7_GKE_PROJECT")
	location := os.Getenv("C7_GKE_LOCATION")
	cluster := os.Getenv("C7_GKE_CLUSTER")
	image := os.Getenv("C7_SANDBOX_IMAGE")
	if project == "" || location == "" || cluster == "" || image == "" {
		t.Skip("set C7_GKE_PROJECT, C7_GKE_LOCATION, C7_GKE_CLUSTER, and C7_SANDBOX_IMAGE (digest-pinned) to run the live integration test")
	}

	ctx := context.Background()
	p, err := New(ctx, Config{ProjectID: project, Location: location, Cluster: cluster, SandboxImage: image})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		if cerr := p.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	}()

	h, err := p.ProvisionSandbox(ctx, interfaces.SandboxSpec{
		SessionID: "itest",
		Subject:   "itest@example.test",
		Persona:   interfaces.PersonaAuthor,
		Egress:    interfaces.EgressPolicy{Allowlist: []string{"https://a.internal", "https://b.internal"}},
		MaxTTL:    5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("ProvisionSandbox: %v", err)
	}
	// Always tear down, even on a mid-test failure.
	defer func() {
		if derr := p.DestroySandbox(ctx, h); derr != nil && p.Live(h) {
			t.Errorf("DestroySandbox cleanup: %v", derr)
		}
	}()

	// The namespace named by the handle must exist.
	runner := &kubeRunner{kubeconfig: p.kubeconfigPath, project: project}
	if out, err := runner.run(ctx, "kubectl", nil, "get", "namespace", h.ID); err != nil {
		t.Fatalf("sandbox namespace %q not found: %v\n%s", h.ID, err, out)
	}

	// Narrowing to a subset must succeed.
	if err := p.ApplyEgressPolicy(ctx, h, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal"}}); err != nil {
		t.Fatalf("ApplyEgressPolicy narrow: %v", err)
	}
	// Widening must be refused.
	if err := p.ApplyEgressPolicy(ctx, h, interfaces.EgressPolicy{Allowlist: []string{"https://a.internal", "https://c.internal"}}); err == nil {
		t.Fatal("ApplyEgressPolicy widened egress beyond the provisioned allowlist")
	}

	// Destroy and confirm the namespace is terminating/gone.
	if err := p.DestroySandbox(ctx, h); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
	if p.Live(h) {
		t.Fatal("sandbox still live after destroy")
	}
	out, err := runner.run(ctx, "kubectl", nil, "get", "namespace", h.ID, "-o", "jsonpath={.status.phase}")
	if err == nil && !strings.Contains(string(out), "Terminating") {
		t.Errorf("namespace %q neither gone nor Terminating after destroy: %q", h.ID, out)
	}
}
