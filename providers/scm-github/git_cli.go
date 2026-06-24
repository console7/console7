package scmgithub

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gitCLI is the real GitTransport: it shells out to `git` (Option A — zero new Go dependency, the
// same posture as cloud-gcp's kubectl/gcloud adapter). It runs ONLY in the control plane.
//
// Token handling: the short-lived installation token is passed to git via a credential helper that
// reads it from the CHILD PROCESS ENV (C7_GIT_TOKEN), so the token value never appears in argv (a
// `ps`-visible leak), never in the remote URL, and never on disk. Any ambient credential helper
// (host keychain, etc.) is disabled first, so only ours can answer — git cannot silently fall back
// to a developer's stored github.com credential.
type gitCLI struct{}

var _ GitTransport = gitCLI{}

// gitCredHelper answers a credential `get` with the App installation token from $C7_GIT_TOKEN
// (username x-access-token). It responds ONLY to `get` (not store/erase), and reads the secret from
// the env so it is never in argv.
//
//nolint:gosec // G101 false positive: a credential-helper SCRIPT template, not a secret value — the token is read from $C7_GIT_TOKEN at runtime, never embedded here; RISKS R-11.
const gitCredHelper = `!f() { test "$1" = get && printf 'username=x-access-token\npassword=%s\n' "$C7_GIT_TOKEN"; }; f`

// gitGlobalArgs builds git's pre-subcommand global flags: -C <dir> to run in a repo, and (when a
// token is in play) credential.helper= to CLEAR any ambient helper followed by ours.
func gitGlobalArgs(token, dir string) []string {
	var a []string
	if dir != "" {
		a = append(a, "-C", dir)
	}
	if token != "" {
		a = append(a, "-c", "credential.helper=", "-c", "credential.helper="+gitCredHelper)
	}
	return a
}

func gitEnv(token string) []string {
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0") // never prompt — fail closed, don't hang
	if token != "" {
		env = append(env, "C7_GIT_TOKEN="+token)
	}
	return env
}

// run executes git with combined output (for diagnosis on error). token (may be "") and dir (may be
// "") become global flags; args is the subcommand.
func (gitCLI) run(ctx context.Context, token, dir string, args ...string) ([]byte, error) {
	full := append(gitGlobalArgs(token, dir), args...)
	cmd := exec.CommandContext(ctx, "git", full...) //nolint:gosec // G204 — literal "git"; remoteURL/branch are provider-derived + validated; token is in env, not argv; RISKS R-10
	cmd.Env = gitEnv(token)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}

// runOut is run's sibling returning STDOUT ONLY (stderr captured separately), so a binary git
// bundle on stdout is not corrupted by git's stderr progress.
func (gitCLI) runOut(ctx context.Context, token, dir string, args ...string) ([]byte, error) {
	full := append(gitGlobalArgs(token, dir), args...)
	cmd := exec.CommandContext(ctx, "git", full...) //nolint:gosec // G204 — see run(); RISKS R-10
	cmd.Env = gitEnv(token)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// CloneBundle clones remoteURL at baseBranch (single-branch) and returns a git bundle of it.
func (g gitCLI) CloneBundle(ctx context.Context, remoteURL, baseBranch, token string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "c7-clone-*")
	if err != nil {
		return nil, fmt.Errorf("scmgithub: mkdtemp for clone: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	repoDir := filepath.Join(dir, "repo")
	// `--` ends option parsing before the positional remote/dir (defence in depth; baseBranch is also
	// seam-validated by isSafeRefName, so it cannot pose as an option).
	if out, err := g.run(ctx, token, "", "clone", "--bare", "--single-branch", "--branch", baseBranch, "--", remoteURL, repoDir); err != nil {
		return nil, fmt.Errorf("scmgithub: clone base %q: %w (%s)", baseBranch, err, bytes.TrimSpace(out))
	}
	bundle, err := g.runOut(ctx, "", repoDir, "bundle", "create", "-", baseBranch)
	if err != nil {
		return nil, fmt.Errorf("scmgithub: bundle base %q: %w", baseBranch, err)
	}
	return bundle, nil
}

// PushBundle imports the working branch from bundle and pushes ONLY that branch ref to remoteURL.
func (g gitCLI) PushBundle(ctx context.Context, remoteURL, branch string, bundle []byte, token string) error {
	dir, err := os.MkdirTemp("", "c7-push-*")
	if err != nil {
		return fmt.Errorf("scmgithub: mkdtemp for push: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	bundlePath := filepath.Join(dir, "in.bundle")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return fmt.Errorf("scmgithub: write bundle: %w", err)
	}
	repoDir := filepath.Join(dir, "repo")
	if out, err := g.run(ctx, "", "", "init", "--bare", repoDir); err != nil {
		return fmt.Errorf("scmgithub: init temp repo: %w (%s)", err, bytes.TrimSpace(out))
	}
	ref := "refs/heads/" + branch + ":refs/heads/" + branch
	if out, err := g.run(ctx, "", repoDir, "fetch", bundlePath, ref); err != nil {
		return fmt.Errorf("scmgithub: import working branch from bundle: %w (%s)", err, bytes.TrimSpace(out))
	}
	// Push EXACTLY the one working branch ref — never --mirror/--all.
	if out, err := g.run(ctx, token, repoDir, "push", remoteURL, ref); err != nil {
		return fmt.Errorf("scmgithub: push working branch %q: %w (%s)", branch, err, bytes.TrimSpace(out))
	}
	return nil
}
