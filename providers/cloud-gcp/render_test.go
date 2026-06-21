package cloudgcp

import (
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

func TestConfigNormalize(t *testing.T) {
	// Defaults are applied for the optional fields.
	got, err := Config{ProjectID: "p", Location: "us-east4", Cluster: "c"}.normalize()
	if err != nil {
		t.Fatalf("normalize valid config: %v", err)
	}
	if got.NamePrefix != DefaultNamePrefix || got.RuntimeClass != DefaultRuntimeClass || got.NodePool != DefaultNamePrefix+"-sandbox" {
		t.Fatalf("defaults not applied: %+v", got)
	}

	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"missing project", Config{Location: "us-east4", Cluster: "c"}},
		{"missing location", Config{ProjectID: "p", Cluster: "c"}},
		{"missing cluster", Config{ProjectID: "p", Location: "us-east4"}},
		{"bad prefix", Config{ProjectID: "p", Location: "us-east4", Cluster: "c", NamePrefix: "Bad_Prefix"}},
		{"prefix trailing hyphen", Config{ProjectID: "p", Location: "us-east4", Cluster: "c", NamePrefix: "x-"}},
	} {
		if _, err := tc.cfg.normalize(); err == nil {
			t.Errorf("%s: expected a validation error", tc.name)
		}
	}
}

func TestJSONScalar_IsYAMLSafe(t *testing.T) {
	// A value carrying YAML-structural characters must be encoded so it cannot break out of its
	// field: the result is a single double-quoted scalar with the structural chars escaped.
	evil := "x\": {injected}\nkind: Secret"
	got := jsonScalar(evil)
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Fatalf("not a quoted scalar: %s", got)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("newline not escaped — YAML-injection risk: %q", got)
	}
}

func TestRenderSandboxPod_SecurityFields(t *testing.T) {
	spec := interfaces.SandboxSpec{
		SessionID: "sess",
		Subject:   "alice@example.test",
		Persona:   interfaces.PersonaAuthor,
		MaxTTL:    90 * time.Second,
	}
	cfg, err := Config{ProjectID: "p", Location: "us-east4", Cluster: "c"}.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	m := string(renderSandboxPod("test-sb-abc", cfg, spec))
	for _, want := range []string{
		"kind: Pod",
		"name: test-sb-abc",
		"namespace: test-sb-abc",
		"runtimeClassName: " + `"gvisor"`, // YAML strips the quotes -> value is gvisor
		"automountServiceAccountToken: false",
		"cloud.google.com/gke-nodepool: " + `"console7-sandbox"`,
		"activeDeadlineSeconds: 90",
		"runAsNonRoot: true",
		"allowPrivilegeEscalation: false",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("pod manifest missing %q\n---\n%s", want, m)
		}
	}
	// The Pod manifest no longer carries the Namespace (the EgressController owns it).
	if strings.Contains(m, "kind: Namespace") {
		t.Errorf("pod manifest should not declare the Namespace (the EgressController owns it)\n%s", m)
	}
}

func TestRenderSandboxPod_TTLFloor(t *testing.T) {
	// A sub-second MaxTTL still yields a hard deadline of at least 1 second (never 0 = unbounded).
	cfg, _ := Config{ProjectID: "p", Location: "us-east4", Cluster: "c"}.normalize()
	m := string(renderSandboxPod("sb", cfg, interfaces.SandboxSpec{MaxTTL: 200 * time.Millisecond}))
	if !strings.Contains(m, "activeDeadlineSeconds: 1") {
		t.Fatalf("sub-second TTL did not floor to 1s:\n%s", m)
	}
}

func TestRenderNamespaceAndEgress(t *testing.T) {
	m := string(renderNamespaceAndEgress("sb", []string{"https://a.internal", "https://b.internal"}))
	for _, want := range []string{
		"kind: Namespace",
		"kind: ConfigMap",
		"kind: NetworkPolicy",
		"policyTypes: [Egress]",
		"console7.dev/egress-proxy",
		"port: 3128", // proxy egress is port-scoped, not all-ports
		"a.internal",
		"namespace: sb",
		// DNS egress is scoped to kube-dns, NOT open to the world.
		"kubernetes.io/metadata.name: kube-system",
		"k8s-app: kube-dns",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("namespace+egress manifest missing %q\n---\n%s", want, m)
		}
	}
	// Guard the exfil hole the review caught: there must be no bare port-53 egress rule without a
	// `to:` peer (which would permit DNS to every destination). Every `ports:` block here must be
	// preceded by a `to:` selector.
	if strings.Count(m, "ports:") != strings.Count(m, "- to:") {
		t.Errorf("a ports rule is missing its `to:` peer (open-egress risk)\n%s", m)
	}
	// An empty allowlist still renders a valid default-deny policy.
	if e := string(renderNamespaceAndEgress("sb", nil)); !strings.Contains(e, "kind: NetworkPolicy") {
		t.Fatalf("empty allowlist did not render a NetworkPolicy:\n%s", e)
	}
}
