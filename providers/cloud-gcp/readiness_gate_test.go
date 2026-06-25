package cloudgcp

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// TestRun_ReadinessGateBeforeFirstExec proves the readiness GATE runs in kubeEngineRunner.Run BEFORE
// the first `kubectl exec` against the pod: Run MUST first wait for the sandbox pod
// `condition=Ready` AND the per-session egress proxy Deployment `condition=Available`, and only then
// exec into the pod (the managed-settings `test -s`, the seed, the engine). Without this ordering the
// first exec races a scheduled-but-not-started pod (the `test -s` misfires "policy absent") and the
// engine's inference egress races a not-yet-listening Squid. The gate lives in Run (it was kept here
// even after Provision gained its own wait), so this exercises Run, not Provision.
//
// It is white-box over the REAL kubeEngineRunner.Run + real kubeRunner, intercepting kubectl/gcloud
// via a fake on PATH that appends each invocation's argv to a log — the same spirit as
// TestRunOut_* exercising a real local `sh`. We assert the ISSUED kubectl args and their ORDER, not a
// live cluster.
func TestRun_ReadinessGateBeforeFirstExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary-on-PATH interception assumes a POSIX shell")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "kubectl.log")

	// A fake `kubectl` that records its full argv (one invocation per line) and exits 0, so Run gets
	// past each step. `wait` and `exec` both flow through it; the log preserves call order.
	fake := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + shquote(logPath) + "\n" +
		"exit 0\n"
	for _, name := range []string{"kubectl", "gcloud"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(fake), 0o755); err != nil { //nolint:gosec // G306 — a fake kubectl/gcloud must carry the exec bit; it lives in t.TempDir()
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	k := &kubeEngineRunner{
		run: &kubeRunner{kubeconfig: filepath.Join(dir, "kubeconfig"), project: "proj"},
		cfg: Config{Workdir: "/workspace"},
	}
	h := interfaces.SandboxHandle{ID: "c7-sb-deadbeefdeadbeefdeadbeefdeadbeef"}
	if _, err := k.Run(context.Background(), h, interfaces.EngineTask{
		SessionID: "s1",
		Repo:      interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:    "feature/x",
		Prompt:    "do the thing",
		Timeout:   time.Minute,
	}); err != nil {
		// A clean tree (the fake emits no diff) returns Changed:false with no error; any error here
		// would be a regression in the run path, surfaced for diagnosis.
		t.Fatalf("Run: %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // G304 — logPath is a test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("read kubectl log: %v", err)
	}
	var calls []string
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(ln) != "" {
			calls = append(calls, ln)
		}
	}
	if len(calls) == 0 {
		t.Fatal("Run issued no kubectl calls")
	}

	// Locate the readiness waits and the first exec.
	idxPodReady, idxProxyAvail, idxFirstExec := -1, -1, -1
	for i, c := range calls {
		isWait := strings.HasPrefix(c, "wait ")
		switch {
		case isWait && strings.Contains(c, "condition=Ready") && strings.Contains(c, "pod/"+h.ID):
			if idxPodReady == -1 {
				idxPodReady = i
			}
		case isWait && strings.Contains(c, "condition=Available") && strings.Contains(c, "deployment/"+proxyServiceName):
			if idxProxyAvail == -1 {
				idxProxyAvail = i
			}
		case strings.HasPrefix(c, "exec "):
			if idxFirstExec == -1 {
				idxFirstExec = i
			}
		}
	}

	if idxPodReady == -1 {
		t.Fatalf("Run did not wait for the sandbox pod condition=Ready; calls: %v", calls)
	}
	if idxProxyAvail == -1 {
		t.Fatalf("Run did not wait for the per-session proxy condition=Available; calls: %v", calls)
	}
	if idxFirstExec == -1 {
		t.Fatalf("Run issued no `kubectl exec` at all; calls: %v", calls)
	}
	// The whole point of the gate: BOTH readiness waits must precede the first exec into the pod.
	if idxPodReady >= idxFirstExec {
		t.Errorf("pod-Ready wait (call %d) must precede the first exec (call %d); calls: %v", idxPodReady, idxFirstExec, calls)
	}
	if idxProxyAvail >= idxFirstExec {
		t.Errorf("proxy-Available wait (call %d) must precede the first exec (call %d); calls: %v", idxProxyAvail, idxFirstExec, calls)
	}

	// The pod-Ready wait must be in the SANDBOX namespace and the proxy-Available wait in the proxy
	// namespace — the gate checks the right targets, not just any two waits.
	if !strings.Contains(calls[idxPodReady], "-n "+h.ID) {
		t.Errorf("pod-Ready wait not scoped to the sandbox namespace %q: %q", h.ID, calls[idxPodReady])
	}
	if !strings.Contains(calls[idxProxyAvail], "-n "+proxyNS(h.ID)) {
		t.Errorf("proxy-Available wait not scoped to the proxy namespace %q: %q", proxyNS(h.ID), calls[idxProxyAvail])
	}
}

// TestRun_VertexResolvesAndThreadsAuthProxyEndpoint proves the F2c-2c flip end to end at the Run level:
// on the Vertex lane, AFTER the readiness waits (incl. the auth-proxy Deployment Available), Run
// resolves THIS session's auth-proxy ClusterIP (authProxyEndpoint) and threads the resolved base URL
// into the engine's exec script — `kubectl exec … claude` carries ANTHROPIC_VERTEX_BASE_URL +
// NO_PROXY pointed at the resolved IP, and NO CLOUDSDK_AUTH_ACCESS_TOKEN / no in-pod credential read.
// It mirrors TestRun_ReadinessGateBeforeFirstExec: a fake kubectl on PATH records argv and, for the
// auth-proxy `get svc … clusterIP` read, prints a fixed IP so the resolve succeeds without a cluster.
func TestRun_VertexResolvesAndThreadsAuthProxyEndpoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary-on-PATH interception assumes a POSIX shell")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "kubectl.log")
	const proxyIP = "10.9.8.7"

	// The fake records argv, and when asked for a Service ClusterIP (the auth-proxy resolve) prints a
	// fixed IP so authProxyEndpoint parses a valid http://<ip>:8080. Everything else exits 0 so Run
	// flows through; the engine exec emits no diff (clean tree ⇒ Changed:false, no error).
	fake := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + shquote(logPath) + "\n" +
		"case \"$*\" in *clusterIP*) printf '" + proxyIP + "' ;; esac\n" +
		"exit 0\n"
	for _, name := range []string{"kubectl", "gcloud"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(fake), 0o755); err != nil { //nolint:gosec // G306 — a fake kubectl/gcloud must carry the exec bit; it lives in t.TempDir()
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// A Vertex-configured provider: VertexModel + AuthProxyImage + VertexRegion make vertexConfigured()
	// true, so waitRunReady gates the auth-proxy and Run resolves + threads its endpoint.
	k := &kubeEngineRunner{
		run: &kubeRunner{kubeconfig: filepath.Join(dir, "kubeconfig"), project: "proj"},
		cfg: Config{Workdir: "/workspace", VertexModel: "claude-haiku-4-5@20251001", VertexRegion: "us-east5"},
	}
	h := interfaces.SandboxHandle{ID: "c7-sb-cafebabecafebabecafebabecafebabe"}
	if _, err := k.Run(context.Background(), h, interfaces.EngineTask{
		SessionID:        "s1",
		Repo:             interfaces.RepoRef{Host: "github.com", Owner: "acme", Name: "app"},
		Branch:           "feature/x",
		Prompt:           "do the thing",
		Timeout:          time.Minute,
		InferenceBackend: interfaces.BackendVertex,
		VertexProjectID:  "acme-prod-123",
		VertexRegion:     "us-east5",
	}); err != nil {
		t.Fatalf("Run (Vertex lane): %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // G304 — logPath is a test-controlled path under t.TempDir()
	if err != nil {
		t.Fatalf("read kubectl log: %v", err)
	}
	// The engine exec script is multi-line (the env-prefixed `claude -p`), so assert over the whole log
	// blob rather than per-call. Line-prefix checks (the wait/resolve) still work per-line.
	blob := string(data)
	lines := strings.Split(blob, "\n")

	var sawAuthProxyWait, sawAuthProxyResolve bool
	for _, c := range lines {
		if strings.HasPrefix(c, "wait ") && strings.Contains(c, "deployment/"+authProxyServiceName) && strings.Contains(c, "-n "+proxyNS(h.ID)) {
			sawAuthProxyWait = true
		}
		if strings.HasPrefix(c, "get svc "+authProxyServiceName) && strings.Contains(c, "-n "+proxyNS(h.ID)) && strings.Contains(c, "clusterIP") {
			sawAuthProxyResolve = true
		}
	}
	if !sawAuthProxyWait {
		t.Errorf("Run did not wait for the Vertex auth-proxy condition=Available; log:\n%s", blob)
	}
	if !sawAuthProxyResolve {
		t.Errorf("Run did not resolve the Vertex auth-proxy ClusterIP; log:\n%s", blob)
	}
	// The resolved auth-proxy endpoint must be threaded into the engine exec, and the retired R-9 lever /
	// the in-sandbox credential read must be absent (the sandbox is credential-free on the Vertex lane).
	if !strings.Contains(blob, "claude -p") {
		t.Fatalf("Run did not exec the engine; log:\n%s", blob)
	}
	for _, want := range []string{
		"ANTHROPIC_VERTEX_BASE_URL='http://" + proxyIP + ":8080'",
		"NO_PROXY='" + proxyIP + "'",
		"no_proxy='" + proxyIP + "'",
		"CLAUDE_CODE_SKIP_VERTEX_AUTH=1",
	} {
		if !strings.Contains(blob, want) {
			t.Errorf("engine exec missing threaded auth-proxy env %q; log:\n%s", want, blob)
		}
	}
	for _, forbidden := range []string{"CLOUDSDK_AUTH_ACCESS_TOKEN", "ANTHROPIC_API_KEY", "_c7cred"} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("Vertex-lane Run must NOT contain %q (sandbox credential-free on this lane); log:\n%s", forbidden, blob)
		}
	}
}
