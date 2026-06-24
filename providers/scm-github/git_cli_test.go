package scmgithub

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runGit is a test fixture helper that runs git against LOCAL repos (no network, no token), used to
// build the source/target repos the real gitCLI methods operate on.
func runGit(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	full := args
	if dir != "" {
		full = append([]string{"-C", dir}, args...)
	}
	cmd := exec.Command("git", full...) //nolint:gosec // G204 — test fixture: literal "git" with test-controlled args
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

// TestGitCLI_CloneBundleAndPushBundle_RoundTrip exercises the real GitTransport end to end against
// LOCAL repos (hermetic — no network, no token): clone a base → bundle it; build a feature-branch
// bundle (standing in for the sandbox's CommitBundle); push it to a "remote". This both covers the
// adapter and proves the clone→bundle→push mechanics the live push→PR bridge depends on.
func TestGitCLI_CloneBundleAndPushBundle_RoundTrip(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	tmp := t.TempDir()
	// Isolate from host git config and supply a commit identity via env (no global config writes).
	t.Setenv("HOME", tmp)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "c7")
	t.Setenv("GIT_AUTHOR_EMAIL", "c7@console7.dev")
	t.Setenv("GIT_COMMITTER_NAME", "c7")
	t.Setenv("GIT_COMMITTER_EMAIL", "c7@console7.dev")
	ctx := context.Background()
	g := gitCLI{}

	// 1. A source repo with a base commit on main.
	src := filepath.Join(tmp, "src")
	runGit(t, "", "init", "-b", "main", src)
	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, src, "add", "-A")
	runGit(t, src, "commit", "-m", "base")

	// 2. CloneBundle the base — token "" since this is a local path (no auth needed); the result must
	// be a real git bundle.
	base, err := g.CloneBundle(ctx, src, "main", "")
	if err != nil {
		t.Fatalf("CloneBundle: %v", err)
	}
	if !bytes.HasPrefix(base, []byte("# v2 git bundle")) && !bytes.HasPrefix(base, []byte("# v3 git bundle")) {
		t.Fatalf("CloneBundle did not return a git bundle, got prefix %q", firstLine(base))
	}

	// 3. Build a feature-branch bundle off the base — this stands in for the sandbox's CommitBundle.
	work := filepath.Join(tmp, "work")
	runGit(t, "", "clone", "--branch", "main", src, work)
	runGit(t, work, "checkout", "-b", "c7/feature")
	if err := os.WriteFile(filepath.Join(work, "NEW.txt"), []byte("change\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "-A")
	runGit(t, work, "commit", "-m", "work")
	feat, err := g.runOut(ctx, "", work, "bundle", "create", "-", "c7/feature")
	if err != nil {
		t.Fatalf("build feature bundle: %v", err)
	}

	// 4. A target "remote" that already has main (like the real repo).
	target := filepath.Join(tmp, "target.git")
	runGit(t, "", "clone", "--bare", src, target)

	// 5. PushBundle the feature branch to the target.
	if err := g.PushBundle(ctx, target, "c7/feature", feat, ""); err != nil {
		t.Fatalf("PushBundle: %v", err)
	}

	// 6. The target now has the working branch with the new file — the push genuinely landed.
	runGit(t, target, "rev-parse", "refs/heads/c7/feature") // fails the test if the ref is absent
	files := runGit(t, target, "ls-tree", "--name-only", "refs/heads/c7/feature")
	if !bytes.Contains(files, []byte("NEW.txt")) {
		t.Errorf("pushed branch missing the engine's change; tree:\n%s", files)
	}
}

func TestGitCLI_CloneBundle_FailsClosedOnBadRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	// A nonexistent local path is a clone failure that must surface as an error, not an empty bundle.
	if _, err := (gitCLI{}).CloneBundle(context.Background(), filepath.Join(t.TempDir(), "nope"), "main", ""); err == nil {
		t.Error("CloneBundle should fail closed on an unreachable remote")
	}
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i]
	}
	return b
}
