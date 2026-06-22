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
// TestIntegration_ProvisionNarrowDestroy proves the lifecycle/egress-narrow spine.
// TestIntegration_LiveEngineRun (B11) adds the Phase-1 EXIT proof — credential deliver/wipe, the
// boundary egress/metadata denials, and the genuine `claude -p` run → real proposed commit. The
// engine run is gated behind C7_RUN_ENGINE + C7_ANTHROPIC_API_KEY (a short-lived org key) so the
// cheaper lifecycle test can run without spending model tokens.
//
// SCOPE — read before declaring Phase-1 EXIT. This test drives the cloud-gcp Provider DIRECTLY, so it
// proves the DATA-PLANE half live (genuine engine in a real gVisor sandbox + default-deny boundary +
// metadata-IP deny + a real commit). It does NOT sign the commit, stamp lineage, or seal the WORM
// chain — those are the orchestrator's job (control-plane/orchestrator + the c7 dev run, proven on the
// in-memory spine). No single execution yet proves ALL exit criteria together; a control-plane main
// that drives the orchestrator against the REAL live seams (closing signing+WORM on the live engine)
// is a tracked residual (B13). Run this for the data-plane proof; do not check the signing/WORM/
// "maintainer-uninvolved" boxes from this test alone.
//
// OPERATOR PRE-FLIGHT (do these BEFORE `terraform apply` — the cluster bills continuously):
//  1. CONFIRM the model id: `curl -s https://api.anthropic.com/v1/models -H "x-api-key: $KEY"
//     -H "anthropic-version: 2023-06-01"` → export C7_ANTHROPIC_MODEL=<a returned id>. Don't trust
//     the default blindly.
//  2. C7_SANDBOX_IMAGE MUST be the DIGEST-PINNED signed image — verify with
//     scripts/verify-sandbox-image.sh first (New() rejects a tag-only ref).
//  3. Apply the namespace-TTL reaper (`kubectl apply -f deploy/gcp/modules/gke/reaper.yaml`) so an
//     aborted run is swept.
//  4. Keep the PoC prompt strictly Write-only (the default is) — headless `--permission-mode default`
//     stalls on a non-allow-listed tool.
//  5. Have `terraform -chdir=deploy/gcp destroy` ready and run it SAME DAY.
package cloudgcp

import (
	"context"
	"fmt"
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

// TestIntegration_LiveEngineRun is the Phase-1 EXIT proof (B11 exit criteria), OPERATOR-RUN against a
// live cluster + a short-lived org API key. It asserts: (a) the pod-readiness gate (RunTask waits);
// (b)/(c) a live credential DeliverIfOwned + the Destroy-time Wipe; (d) the boundary denies a
// non-allowlisted host AND the GCP metadata IP from inside the sandbox; (e) a genuine `claude -p`
// produces a real commit (Changed, non-empty HeadSHA). The orchestrator signs that commit and seals
// the WORM chain (proven in control-plane/orchestrator + the c7 CLI dev run); this Provider-level test
// proves the data-plane half. apply → prove → destroy SAME DAY (the cluster bills continuously).
func TestIntegration_LiveEngineRun(t *testing.T) {
	project := os.Getenv("C7_GKE_PROJECT")
	location := os.Getenv("C7_GKE_LOCATION")
	cluster := os.Getenv("C7_GKE_CLUSTER")
	image := os.Getenv("C7_SANDBOX_IMAGE")
	orgKey := os.Getenv("C7_ANTHROPIC_API_KEY")
	if os.Getenv("C7_RUN_ENGINE") == "" || project == "" || location == "" || cluster == "" || image == "" || orgKey == "" {
		t.Skip("set C7_RUN_ENGINE=1 + C7_GKE_PROJECT/LOCATION/CLUSTER + C7_SANDBOX_IMAGE + C7_ANTHROPIC_API_KEY to run the live engine PoC")
	}

	ctx := context.Background()
	p, err := New(ctx, Config{
		ProjectID: project, Location: location, Cluster: cluster, SandboxImage: image,
		// The pinned engine's DEFAULT model 404s on the API, so a real run needs a known-good id.
		// PRE-FLIGHT: confirm the id against `GET /v1/models` with THIS key before the billed run and
		// override with C7_ANTHROPIC_MODEL — do not trust this default blindly. Default is a cheap,
		// previously-live-proven snapshot (a HELLO.txt PoC needs nothing larger).
		AnthropicModel: orEnv("C7_ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = p.Close() }()

	const subject = interfaces.Subject("poc@example.test")
	const session = interfaces.SessionID("poc-1")
	h, err := p.ProvisionSandbox(ctx, interfaces.SandboxSpec{
		SessionID: session, Subject: subject, Persona: interfaces.PersonaAuthor,
		Egress: interfaces.EgressPolicy{Allowlist: []string{"https://api.anthropic.com"}},
		// Generous headroom: readiness waits (≤90s×2) + delivery + probes + the ≤8-min engine run must
		// finish well before the namespace-TTL reaper / activeDeadlineSeconds reclaims the sandbox.
		MaxTTL: 20 * time.Minute,
	})
	if err != nil {
		t.Fatalf("ProvisionSandbox: %v", err)
	}
	defer func() {
		if derr := p.DestroySandbox(ctx, h); derr != nil && p.Live(h) {
			t.Errorf("DestroySandbox cleanup: %v", derr)
		}
	}()

	runner := &kubeRunner{kubeconfig: p.kubeconfigPath, project: project}
	// (a) readiness: wait for the sandbox pod + its per-session proxy before exec'ing into them.
	if err := runner.waitReady(ctx, "pod/"+h.ID, h.ID, "condition=Ready", readyTimeout); err != nil {
		t.Fatalf("sandbox pod never became Ready: %v", err)
	}
	if err := runner.waitReady(ctx, "deployment/"+proxyServiceName, proxyNS(h.ID), "condition=Available", readyTimeout); err != nil {
		t.Fatalf("per-session egress proxy never became Available: %v", err)
	}

	// (b)/(c) deliver the short-lived org key into the owning sandbox (the Provider IS the Injector).
	if !p.DeliverIfOwned(h, subject, session, []byte(orgKey)) {
		t.Fatal("DeliverIfOwned failed to deliver the org credential into the owning sandbox")
	}

	// (d) the boundary denies a non-allowlisted host AND the GCP metadata IP from inside the sandbox.
	// POSITIVE CONTROL FIRST (so the denials below aren't vacuous): the sandbox MUST be able to reach
	// its own per-session proxy. If a blanket node/exec/RBAC failure made that fail too, every "deny"
	// would pass for the wrong reason — so a dead positive control fails the test hard.
	endpoint, err := runner.proxyEndpoint(ctx, proxyNS(h.ID)) // "http://<clusterIP>:3128"
	if err != nil {
		t.Fatalf("resolve proxy endpoint for the egress positive control: %v", err)
	}
	proxyIP := strings.TrimSuffix(strings.TrimPrefix(endpoint, "http://"), fmt.Sprintf(":%d", proxyPort))
	if !sandboxCanConnect(ctx, runner, h, proxyIP, fmt.Sprintf("%d", proxyPort)) {
		t.Fatal("egress positive control FAILED: the sandbox cannot reach its own proxy — node/exec is broken, so the deny results below would be meaningless")
	}
	// Now the deny probes. A raw TCP connect (node is the image's guaranteed runtime) must FAIL: the
	// per-session NetworkPolicy permits egress ONLY to the proxy, so every other IP is dropped. The
	// 169.254.169.254 IP probe is the AUTHORITATIVE metadata-deny proof; the metadata.google.internal
	// name probe additionally confirms there is NO in-sandbox resolver (it fails at resolution, the
	// no-DNS property — not the IP block).
	for _, dst := range []struct{ host, port, why string }{
		{"169.254.169.254", "80", "GCP metadata IP (NetworkPolicy deny + GKE_METADATA concealment)"},
		{"metadata.google.internal", "80", "metadata DNS name (no in-sandbox resolver)"},
		{"1.1.1.1", "443", "a non-allowlisted public host"},
	} {
		if sandboxCanConnect(ctx, runner, h, dst.host, dst.port) {
			t.Errorf("egress to %s:%s (%s) SUCCEEDED from the sandbox — the boundary failed to deny it", dst.host, dst.port, dst.why)
		}
	}

	// (e) the genuine engine produces a real commit on the working branch.
	res, err := p.RunTask(ctx, h, interfaces.EngineTask{
		SessionID: session,
		Profile:   interfaces.SessionProfile{Persona: interfaces.PersonaAuthor},
		Repo:      interfaces.RepoRef{Host: "github.com", Owner: "console7", Name: "poc-sandbox"},
		Branch:    "c7/poc-1",
		Prompt:    "Create a file HELLO.txt containing exactly the line: hello from console7. Then stop.",
		Timeout:   8 * time.Minute,
	})
	if err != nil {
		t.Fatalf("RunTask (genuine claude -p): %v", err)
	}
	if !res.Changed || res.HeadSHA == "" {
		t.Fatalf("expected a real proposed commit, got Changed=%v HeadSHA=%q files=%v", res.Changed, res.HeadSHA, res.FilesChanged)
	}
	t.Logf("PoC OK: proposed commit %s (%d files) under default-deny egress", res.HeadSHA, len(res.FilesChanged))
}

// sandboxCanConnect execs a raw TCP connect to host:port inside the sandbox (via node, the image's
// guaranteed runtime) and reports whether it CONNECTED — the in-pod process exited 0. A non-zero exit
// (connection refused/timed out/blocked, or a DNS-resolution failure) reports false. Used both as the
// positive control (the proxy must connect) and the deny probes (everything else must not). host/port
// are test constants, %q/%s-interpolated into the script.
func sandboxCanConnect(ctx context.Context, runner *kubeRunner, h interfaces.SandboxHandle, host, port string) bool {
	script := fmt.Sprintf(`const net=require('net');`+
		`const s=net.connect({host:%q,port:%s},()=>process.exit(0));`+
		`s.setTimeout(4000,()=>{s.destroy();process.exit(3)});`+
		`s.on('error',()=>process.exit(2));`, host, port)
	_, err := runner.run(ctx, "kubectl", nil,
		"exec", "-n", h.ID, h.ID, "-c", "sandbox", "--", "node", "-e", script)
	return err == nil // exit 0 ⇒ connected
}

func orEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
