package cloudgcp

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestRunOut_StdoutOnlyBinarySafe proves runOut returns STDOUT ONLY — stderr is not interleaved into
// the payload — which is what keeps an extracted git bundle (binary, on stdout) from being corrupted
// by git's progress/notices on stderr. It runs a real local `sh`, not kubectl.
func TestRunOut_StdoutOnlyBinarySafe(t *testing.T) {
	r := &kubeRunner{}
	// Emit bytes including a NUL on stdout, and noise on stderr; only the stdout bytes must come back.
	out, err := r.runOut(context.Background(), "sh", nil, "-c", `printf 'AB\000CD'; printf 'STDERR-NOISE' >&2`)
	if err != nil {
		t.Fatalf("runOut: %v", err)
	}
	if want := []byte{'A', 'B', 0, 'C', 'D'}; !bytes.Equal(out, want) {
		t.Errorf("runOut returned %q, want exactly the stdout bytes %q (no stderr, no corruption)", out, want)
	}
	if bytes.Contains(out, []byte("STDERR-NOISE")) {
		t.Errorf("runOut leaked stderr into the payload: %q", out)
	}
}

// TestRunOut_ErrorSurfacesStderr proves a failing command returns an error that surfaces stderr (for
// diagnosis) and no partial stdout payload the caller might mistake for a valid bundle.
func TestRunOut_ErrorSurfacesStderr(t *testing.T) {
	r := &kubeRunner{}
	out, err := r.runOut(context.Background(), "sh", nil, "-c", `echo boom >&2; exit 3`)
	if err == nil {
		t.Fatal("expected an error from a non-zero exit")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error should surface stderr for diagnosis, got: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("a failed runOut must not return a payload, got %q", out)
	}
}

// TestRunOut_FeedsStdin proves runOut feeds stdin through (the seed path writes the base bundle into
// the pod via stdin; the same plumbing is exercised here without kubectl).
func TestRunOut_FeedsStdin(t *testing.T) {
	r := &kubeRunner{}
	out, err := r.runOut(context.Background(), "cat", []byte("piped-payload"))
	if err != nil {
		t.Fatalf("runOut(cat): %v", err)
	}
	if string(out) != "piped-payload" {
		t.Errorf("stdin not fed through: got %q", out)
	}
}
