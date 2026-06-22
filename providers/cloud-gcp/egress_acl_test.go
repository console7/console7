package cloudgcp

import (
	"strings"
	"testing"
)

func TestEgressAllowlistToSquidACL_Valid(t *testing.T) {
	acl, err := egressAllowlistToSquidACL([]string{"https://api.anthropic.com", "http://internal.example:8080"})
	if err != nil {
		t.Fatalf("valid allowlist: %v", err)
	}
	for _, want := range []string{
		"acl c7_dst_0 dstdomain api.anthropic.com",
		"acl c7_port_0 port 443", // https default
		"http_access allow c7_dst_0 c7_port_0",
		"acl c7_dst_1 dstdomain internal.example",
		"acl c7_port_1 port 8080", // explicit port
		"http_access allow c7_dst_1 c7_port_1",
	} {
		if !strings.Contains(acl, want) {
			t.Errorf("ACL missing %q\n---\n%s", want, acl)
		}
	}
	// Each entry pairs its OWN host with its OWN port — never cross-allowed.
	if strings.Contains(acl, "c7_dst_0 c7_port_1") || strings.Contains(acl, "c7_dst_1 c7_port_0") {
		t.Errorf("ACL cross-paired a host with another entry's port (over-broad):\n%s", acl)
	}
}

func TestEgressAllowlistToSquidACL_EmptyIsDenyAll(t *testing.T) {
	// Empty allowlist → empty fragment; the proxy's trailing `http_access deny all` denies everything.
	acl, err := egressAllowlistToSquidACL(nil)
	if err != nil || strings.TrimSpace(acl) != "" {
		t.Fatalf("empty allowlist should yield empty fragment, got err=%v acl=%q", err, acl)
	}
}

func TestEgressAllowlistToSquidACL_FailsClosedOnMalformed(t *testing.T) {
	// EVERY bad entry must ERROR (fail closed), never be silently dropped — so a malformed allowlist
	// can't collapse into a vacuous/over-broad perimeter.
	for _, tc := range []struct {
		name, entry string
	}{
		{"no scheme (bare host)", "api.anthropic.com"},
		{"unsupported scheme", "ftp://api.anthropic.com"},
		{"file scheme", "file:///etc/passwd"},
		{"empty host", "https://"},
		{"host with space (injection)", "https://api.anthropic.com evil"},
		{"host with newline (squid-directive injection)", "https://api.anthropic.com\nhttp_access allow all"},
		{"wildcard host", "https://*.anthropic.com"},
		{"leading-dot host", "https://.anthropic.com"},
		{"port out of range", "https://api.anthropic.com:99999"},
		{"non-numeric port", "https://api.anthropic.com:https"},
		{"empty string", ""},
		{"IPv4-literal host (dstdomain mishandles it)", "https://10.0.0.5"},
		{"IPv4-literal host with port", "https://10.0.0.5:8443"},
	} {
		if _, err := egressAllowlistToSquidACL([]string{tc.entry}); err == nil {
			t.Errorf("%s: expected fail-closed error for %q, got none", tc.name, tc.entry)
		}
	}
	// A single bad entry among good ones still fails the WHOLE transform (no partial/over-broad config).
	if _, err := egressAllowlistToSquidACL([]string{"https://api.anthropic.com", "not a url at all ::::"}); err == nil {
		t.Error("a malformed entry among valid ones must fail the whole transform (fail closed)")
	}
}

func TestIsNumericPort(t *testing.T) {
	for _, ok := range []string{"1", "80", "443", "8080", "65535"} {
		if !isNumericPort(ok) {
			t.Errorf("%q should be a valid port", ok)
		}
	}
	for _, bad := range []string{"", "0", "65536", "99999", "44a", "-1", " 443", "443 "} {
		if isNumericPort(bad) {
			t.Errorf("%q should NOT be a valid port", bad)
		}
	}
}
