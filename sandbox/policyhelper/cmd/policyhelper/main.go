// Command policyhelper renders a session's LOCKED managed-settings + hooks into the sandbox base
// image's locked paths, from a SessionProfile JSON. The base image's entrypoint runs it at session
// start (and it is usable standalone for the local dogfood). It writes the managed-settings
// read-only and the hooks executable; both live under root-owned paths the agent user cannot alter.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/console7/console7/sandbox/policyhelper"
	"github.com/console7/console7/sdk/interfaces"
)

func main() {
	if err := run(os.Stdin, ""); err != nil {
		fmt.Fprintln(os.Stderr, "policyhelper:", err)
		os.Exit(1)
	}
}

// run reads a SessionProfile JSON from stdin and writes the rendered managed-settings + hook
// scripts under root (empty = the absolute locked paths). root is a test seam; production passes "".
// Reading from stdin (the control plane pipes the profile in) keeps no attacker-influenced file
// path in play. A render that fails closed (unknown persona) is surfaced, not written.
func run(stdin io.Reader, root string) error {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read session profile: %w", err)
	}

	var profile interfaces.SessionProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("parse session profile: %w", err)
	}
	r, err := policyhelper.Render(profile)
	if err != nil {
		return err
	}
	// Only the managed-settings is rendered; the hooks it references are baked binaries in the image
	// (policyhelper.TripwirePath), not files to write.
	return writeFile(root, policyhelper.ManagedSettingsPath, r.ManagedSettings, 0o444)
}

func writeFile(root, path string, content []byte, mode os.FileMode) error {
	full := filepath.Join(root, path)
	// 0750: owner (root) + group only, no world bits. In the image the locked dirs are root:sandbox
	// setgid, so the non-root agent traverses via its group; root owns and writes, the agent never
	// can (the file modes 0444/0555 are read/exec-only). This is the no-op path in the image (the
	// Dockerfile pre-creates the dirs); it is exercised for a fresh root in tests / the dogfood.
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return fmt.Errorf("mkdir for %s: %w", path, err)
	}
	if err := os.WriteFile(full, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile's mode is filtered through the process umask, so a hardened root umask (e.g. 077)
	// would create the policy 0400 — unreadable by the non-root agent, so the engine would start
	// without it. Chmod is NOT umask-filtered; enforce the intended bits explicitly.
	if err := os.Chmod(full, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
