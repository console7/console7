package cloudgcp

import (
	"strings"
	"testing"
	"time"

	"github.com/console7/console7/sdk/interfaces"
)

// testImage is a syntactically valid digest-pinned sandbox image for the construction tests (the
// digest is fake but well-formed: 64 lowercase hex). SandboxImage is required + digest-pinned.
var testImage = "ghcr.io/console7/sandbox-base@sha256:" + strings.Repeat("a", 64)

func TestConfigNormalize(t *testing.T) {
	// Defaults are applied for the optional fields.
	got, err := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage}.normalize()
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
		{"missing image", Config{ProjectID: "p", Location: "us-east4", Cluster: "c"}},
		{"tag-only image (not digest-pinned)", Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: "ghcr.io/console7/sandbox-base:v1"}},
		{"image with short/invalid digest", Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: "ghcr.io/console7/sandbox-base@sha256:abc"}},
		{"malformed double-digest image", Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: "ghcr.io/console7/sandbox-base@sha256:" + strings.Repeat("a", 64) + "@sha256:" + strings.Repeat("b", 64)}},
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

	// U+2028/U+2029/U+0085 are line breaks to a YAML 1.1 reader but encoding/json emits them
	// literally; jsonScalar must escape them so any future caller's value is unconditionally safe.
	for _, lb := range []string{"\u2028", "\u2029", "\u0085"} {
		out := jsonScalar("a" + lb + "kind: Secret")
		if strings.Contains(out, lb) {
			t.Errorf("jsonScalar left a raw YAML-1.1 line separator %q unescaped: %q", lb, out)
		}
	}
}

func TestRenderSandboxPod_SecurityFields(t *testing.T) {
	spec := interfaces.SandboxSpec{
		SessionID: "sess",
		Subject:   "alice@example.test",
		Persona:   interfaces.PersonaAuthor,
		MaxTTL:    90 * time.Second,
	}
	cfg, err := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage}.normalize()
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

func TestRenderSandboxPod_ImageAndModelEnv(t *testing.T) {
	// With a model set, the pod pins the digest image and renders the ANTHROPIC_MODEL env.
	cfg, err := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage, AnthropicModel: "claude-known-good-1"}.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	m := string(renderSandboxPod("sb", cfg, interfaces.SandboxSpec{MaxTTL: time.Minute}))
	if !strings.Contains(m, "image: "+jsonScalar(testImage)) {
		t.Errorf("pod does not pin the digest image %q:\n%s", testImage, m)
	}
	if strings.Contains(m, "pause") || strings.Contains(m, "google-containers") {
		t.Errorf("pod still references the removed placeholder image:\n%s", m)
	}
	for _, want := range []string{"name: ANTHROPIC_MODEL", `value: "claude-known-good-1"`} {
		if !strings.Contains(m, want) {
			t.Errorf("pod missing inference env %q:\n%s", want, m)
		}
	}

	// With no model, NO ANTHROPIC_MODEL env is rendered (never an empty-valued footgun var).
	cfg2, _ := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage}.normalize()
	m2 := string(renderSandboxPod("sb", cfg2, interfaces.SandboxSpec{MaxTTL: time.Minute}))
	if strings.Contains(m2, "ANTHROPIC_MODEL") || strings.Contains(m2, "env:") {
		t.Errorf("empty AnthropicModel should render no env block:\n%s", m2)
	}
	// And the API key is NEVER rendered into the pod spec (it is injected at run time).
	if strings.Contains(m, "ANTHROPIC_API_KEY") {
		t.Errorf("the API key must not be rendered into the pod spec (inject at run time):\n%s", m)
	}
}

func TestRenderSandboxPod_ManagedSettingsLock(t *testing.T) {
	cfg, _ := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage}.normalize()
	m := string(renderSandboxPod("test-sb-abc", cfg, interfaces.SandboxSpec{Persona: interfaces.PersonaAuthor, MaxTTL: time.Minute}))

	// The session-profile ConfigMap carries the resolved persona for the init renderer.
	for _, want := range []string{
		"kind: ConfigMap",
		"name: test-sb-abc-session-profile",
		"profile.json:",
		"author", // the persona the init container renders the locked settings from
	} {
		if !strings.Contains(m, want) {
			t.Errorf("manifest missing session-profile bit %q\n%s", want, m)
		}
	}

	// The init container renders the locked policy (non-root, PSA-restricted) into a memory emptyDir.
	for _, want := range []string{
		"initContainers:",
		"name: render-policy",
		"console7-policyhelper < /etc/console7/session-profile/profile.json",
		"medium: Memory",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("manifest missing init-render bit %q\n%s", want, m)
		}
	}

	// The LOCK: the ENGINE container mounts the managed-settings volume READ-ONLY (the kernel denies
	// writes to a readOnly mount regardless of uid/mode, so the non-root engine cannot overwrite its
	// own policy). This exact sequence is unique to the engine mount (the init mount has no readOnly).
	lockMount := "          mountPath: /etc/claude-code\n          readOnly: true"
	if !strings.Contains(m, lockMount) {
		t.Errorf("engine container does not mount managed-settings READ-ONLY (the policy lock):\n%s", m)
	}

	// PSA-restricted-compliant securityContext (so the namespace's enforce:restricted admits the pod
	// and a hostNetwork metadata-bypass is structurally impossible).
	for _, want := range []string{
		"seccompProfile:",
		"type: RuntimeDefault",
		"drop: [ALL]",
		"fsGroup: 65532",
		"runAsNonRoot: true",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("manifest missing PSA-restricted securityContext bit %q\n%s", want, m)
		}
	}
}

func TestRenderSandboxPod_TTLFloor(t *testing.T) {
	// A sub-second MaxTTL still yields a hard deadline of at least 1 second (never 0 = unbounded).
	cfg, _ := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage}.normalize()
	m := string(renderSandboxPod("sb", cfg, interfaces.SandboxSpec{MaxTTL: 200 * time.Millisecond}))
	if !strings.Contains(m, "activeDeadlineSeconds: 1") {
		t.Fatalf("sub-second TTL did not floor to 1s:\n%s", m)
	}
}

func TestNetworkPolicyEnforced(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{"\tADVANCED_DATAPATH", true},     // Dataplane V2 enforces inherently
		{"True\t", true},                  // legacy network-policy addon enabled
		{"True\tADVANCED_DATAPATH", true}, // both
		{"\tLEGACY_DATAPATH", false},      // Standard, no addon, Dataplane V1 → inert
		{"False\tLEGACY_DATAPATH", false}, // addon explicitly off
		{"", false},                       // empty/unrecognised → fail closed
		{"something unexpected", false},   // garbage → fail closed
	} {
		if got := networkPolicyEnforced(tc.out); got != tc.want {
			t.Errorf("networkPolicyEnforced(%q) = %v, want %v", tc.out, got, tc.want)
		}
	}
}

func TestNodePoolMetadataConcealed(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"GKE_METADATA", true},   // GKE metadata server conceals the node SA
		{"gke_metadata\n", true}, // case/whitespace-insensitive
		{"GCE_METADATA", false},  // exposes the node SA token
		{"EXPOSE", false},
		{"", false}, // unset → fail closed
	} {
		if got := nodePoolMetadataConcealed(tc.mode); got != tc.want {
			t.Errorf("nodePoolMetadataConcealed(%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestRenderSandboxPod_ResourceCaps(t *testing.T) {
	cfg, _ := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage}.normalize()
	m := string(renderSandboxPod("sb", cfg, interfaces.SandboxSpec{MaxTTL: time.Minute}))
	for _, want := range []string{"resources:", "requests:", "limits:", "ephemeral-storage:"} {
		if !strings.Contains(m, want) {
			t.Errorf("pod manifest missing resource cap %q (untrusted pod must be bounded)\n%s", want, m)
		}
	}
}

func TestRenderNamespaceAndEgress(t *testing.T) {
	m := string(renderNamespaceAndEgress("sb", []string{"https://a.internal", "https://b.internal"}))
	for _, want := range []string{
		"kind: Namespace",
		"kind: ConfigMap",
		"kind: NetworkPolicy",
		"policyTypes: [Egress, Ingress]", // default-deny ingress AND egress
		"console7.dev/egress-proxy",
		"port: 3128", // proxy egress is port-scoped, not all-ports
		"a.internal",
		"namespace: sb",
		"pod-security.kubernetes.io/enforce: restricted", // PSA closes the hostNetwork metadata-bypass
		"pod-security.kubernetes.io/enforce-version: latest",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("namespace+egress manifest missing %q\n---\n%s", want, m)
		}
	}
	// The sandbox gets NO in-cluster DNS (no kube-dns rule, no open port-53): name resolution is
	// the proxy's job, and in-sandbox DNS would be a tunnelling exfil path (THREAT-MODEL.md).
	for _, forbidden := range []string{"kube-dns", "port: 53"} {
		if strings.Contains(m, forbidden) {
			t.Errorf("manifest unexpectedly grants in-sandbox DNS (%q) — exfil channel\n%s", forbidden, m)
		}
	}
	// Defence against re-introducing an open-egress rule: every `ports:` block must have a `to:`
	// peer (a ports rule with no peer permits those ports to every destination).
	if strings.Count(m, "ports:") != strings.Count(m, "- to:") {
		t.Errorf("a ports rule is missing its `to:` peer (open-egress risk)\n%s", m)
	}
	// There is exactly one egress allow rule (to the proxy); ingress has none (default-deny).
	if n := strings.Count(m, "- to:"); n != 1 {
		t.Errorf("expected exactly one egress allow rule (the proxy), got %d\n%s", n, m)
	}
	// An empty allowlist still renders a valid default-deny policy, and the allowlist wire format
	// MUST be the canonical "[]" — never JSON "null" — so a PR-3 proxy parser can't read deny-all
	// as "no policy → allow-all". Both nil and an empty slice render "[]".
	for _, empty := range [][]string{nil, {}} {
		e := string(renderNamespaceAndEgress("sb", empty))
		if !strings.Contains(e, "kind: NetworkPolicy") {
			t.Fatalf("empty allowlist did not render a NetworkPolicy:\n%s", e)
		}
		if !strings.Contains(e, `allowlist.json: "[]"`) {
			t.Errorf("empty allowlist did not render the canonical []: \n%s", e)
		}
		if strings.Contains(e, "null") {
			t.Errorf("empty allowlist rendered JSON null (fail-open contract trap)\n%s", e)
		}
	}
}

func TestNonEmptyLines(t *testing.T) {
	got := nonEmptyLines("main.go\n\n  README.md \n\t\npkg/x.go\n")
	want := []string{"main.go", "README.md", "pkg/x.go"}
	if len(got) != len(want) {
		t.Fatalf("nonEmptyLines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
	if len(nonEmptyLines("   \n\t\n")) != 0 {
		t.Error("expected no lines from all-blank input")
	}
}

func TestConfigNormalize_WorkdirDefault(t *testing.T) {
	got, err := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage}.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got.Workdir != DefaultWorkdir {
		t.Errorf("Workdir default = %q, want %q", got.Workdir, DefaultWorkdir)
	}
	// An explicit Workdir is preserved.
	got2, _ := Config{ProjectID: "p", Location: "us-east4", Cluster: "c", SandboxImage: testImage, Workdir: "/src"}.normalize()
	if got2.Workdir != "/src" {
		t.Errorf("explicit Workdir not preserved: %q", got2.Workdir)
	}
}
