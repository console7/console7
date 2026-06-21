package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/console7/console7/sandbox/policyhelper"
)

func TestRun_WritesManagedSettingsReadOnly(t *testing.T) {
	root := t.TempDir()
	profile := `{"Persona":"operate","EgressAllowlist":["https://a.internal"]}`
	if err := run(strings.NewReader(profile), root); err != nil {
		t.Fatalf("run: %v", err)
	}
	// managed-settings written read-only (the agent cannot rewrite its own policy).
	ms := filepath.Join(root, policyhelper.ManagedSettingsPath)
	info, err := os.Stat(ms)
	if err != nil {
		t.Fatalf("managed-settings not written: %v", err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Errorf("managed-settings is writable (mode %v); must be read-only", info.Mode().Perm())
	}
}

func TestRun_FailsClosedOnBadProfile(t *testing.T) {
	root := t.TempDir()
	if err := run(strings.NewReader(`{"Persona":"saboteur"}`), root); err == nil {
		t.Fatal("expected an unknown persona to fail closed")
	}
	if err := run(strings.NewReader(`not json`), root); err == nil {
		t.Fatal("expected unparseable profile to error")
	}
	// Nothing should have been written on the fail-closed path.
	if _, err := os.Stat(filepath.Join(root, policyhelper.ManagedSettingsPath)); !os.IsNotExist(err) {
		t.Error("managed-settings was written despite a fail-closed render")
	}
}
