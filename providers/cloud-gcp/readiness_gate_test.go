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
