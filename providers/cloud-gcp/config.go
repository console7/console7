package cloudgcp

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// DefaultNamePrefix matches deploy/gcp/modules/networking + modules/gke name_prefix default,
// so the sandbox resources this provider names line up with the cluster/node-pool/tag those
// modules provision.
const DefaultNamePrefix = "console7"

// DefaultRuntimeClass is the Kubernetes RuntimeClass GKE Sandbox (gVisor) registers.
const DefaultRuntimeClass = "gvisor"

// DefaultWorkdir is the in-pod repository checkout the engine works and commits in — the
// sandbox base image's workspace (sandbox/base-image/Dockerfile: home/WORKDIR /workspace).
const DefaultWorkdir = "/workspace"

// Config configures the production provider (New), which dials the cluster via the adopter's
// pinned kubectl + gcloud. The cluster, the gVisor node pool, and the sandbox network tag are
// provisioned by deploy/gcp/modules/gke (PR-2b); these fields are that module's outputs.
type Config struct {
	// ProjectID is the adopter's GCP project that owns the GKE cluster.
	ProjectID string
	// Location is the cluster's region or zone (e.g. "us-east4"), passed to
	// `gcloud container clusters get-credentials`.
	Location string
	// Cluster is the GKE cluster name (modules/gke output).
	Cluster string
	// NamePrefix prefixes the per-session namespace/pod names and selects the sandbox node
	// pool. Defaults to DefaultNamePrefix; must match the deploy modules' name_prefix.
	NamePrefix string
	// NodePool is the gVisor (sandboxed) node pool the sandbox pods are pinned to (modules/gke
	// output). The pool runs the GKE metadata server in GKE_METADATA mode, which conceals the node
	// service account (a sandbox pod, bound to no KSA and with automountServiceAccountToken=false,
	// gets no node-local metadata credential) — the authoritative metadata block. New refuses to
	// construct against a pool whose workloadMetadataConfig.mode is not GKE_METADATA. Defaults to
	// "<NamePrefix>-sandbox".
	NodePool string
	// RuntimeClass is the gVisor RuntimeClass name. Defaults to DefaultRuntimeClass.
	RuntimeClass string
	// Workdir is the checked-out repository path inside the sandbox pod the engine works and commits
	// in (the base image's workspace). RunTask reads the produced commit from here. Defaults to
	// DefaultWorkdir.
	Workdir string
	// SandboxImage is the reference to the signed sandbox base image the pod runs (e.g.
	// "ghcr.io/console7/sandbox-base@sha256:..."). It MUST be DIGEST-PINNED: normalize rejects a
	// tag-only reference, because a tag is mutable and is NOT what the kubelet content-addresses —
	// pinning the digest is the supply-chain gate that the bytes which run are the bytes the release
	// pipeline signed (.github/workflows/sandbox-image-release.yml; verify it first with
	// scripts/verify-sandbox-image.sh). NOTE: this guarantees the digest is content-addressed at the
	// kubelet; it is NOT admission-enforced — a binding admission policy that REQUIRES a valid
	// signature (so an actor with cluster-write cannot schedule a different image) is Phase-2
	// hardening, not this field. Required.
	SandboxImage string
	// AnthropicModel pins the engine's ANTHROPIC_MODEL (the org-API lane). It is rendered into the
	// sandbox container's env. The pinned engine's DEFAULT model id 404s on the API, so a known-good
	// id MUST be supplied for a working run — but it is optional at construction (lifecycle
	// provision/destroy needs no model), and when empty no ANTHROPIC_MODEL is rendered (the engine
	// falls back to its default, which currently 404s). The Anthropic API KEY is NOT set here: it is
	// a secret injected into the pod at run time (the SecretsProvider injection path), never rendered
	// into the pod spec. Vertex routing env is a separate lane (see VertexModel).
	AnthropicModel string
	// VertexModel pins the engine's model on the VERTEX lane. Vertex publisher model ids use the
	// "@"-date form (e.g. "claude-haiku-4-5@20251001" or "<id>@latest"), which is a DIFFERENT
	// namespace from the Anthropic-API "-"-snapshot form in AnthropicModel — they are not
	// interchangeable, so the Vertex lane carries its own pin. It is optional at construction
	// (lifecycle provision/destroy needs no model) and used only when a session resolves to the
	// Vertex lane; normalize rejects a value that is not in the "@"-form (so an Anthropic-API id
	// fat-fingered into this slot fails at construction, not as a confusing 404 in the sandbox).
	// Like AnthropicModel it is a routing fact, never a credential.
	//
	// It ALSO doubles as the provider's lane gate at provision/Set time: the inference LANE is
	// resolved by the orchestrator only AFTER ProvisionSandbox/Set (it rides on EngineTask, at
	// RunTask time), and is NOT threaded into SandboxSpec or the EgressController seam — so the
	// renderers cannot learn "this is a Vertex session" at the moment they emit the per-session
	// topology. A non-empty VertexModel means this provider IS configured for the Vertex lane, and
	// is the config-derived signal renderVertexAuthProxy / renderNamespaceAndEgress gate on
	// (vertexConfigured). See those renderers and docs/RISKS.md for the lane-gating rationale.
	VertexModel string
	// AuthProxyImage is the reference to the signed, digest-pinned Vertex auth-proxy image the
	// per-session auth-proxy pod runs (e.g. "ghcr.io/console7/vertex-auth-proxy@sha256:..."). It is
	// a SEPARATE, separately-signed artifact from SandboxImage (the thing that holds the Vertex
	// bearer must not share a build identity with the thing that runs untrusted code — ARCHITECTURE.md
	// §6.4; sandbox/vertex-auth-proxy/README.md), built/signed by
	// .github/workflows/auth-proxy-image-release.yml and verified with scripts/verify-auth-proxy-image.sh.
	// Like SandboxImage it MUST be DIGEST-PINNED (a tag is mutable and is not what the kubelet
	// content-addresses) and the adopter mirrors the verified image into their own in-tenancy
	// Artifact Registry before use (no runtime maintainer path; tenet 1).
	//
	// It is OPTIONAL at construction (the Anthropic-API lane needs no auth-proxy); normalize rejects
	// only a NON-empty value that is not digest-pinned. It is REQUIRED to actually render the
	// per-session auth-proxy: a provider configured for the Vertex lane (VertexModel set) but with no
	// AuthProxyImage fails closed at normalize, since a Vertex session would otherwise have no
	// credential-attaching gateway to reach.
	AuthProxyImage string
	// VertexRegion / VertexProject are the per-provider Vertex routing facts the auth-proxy pod is
	// configured with at render time (its CLOUD_ML_REGION / C7_AUTHPROXY_PROJECT). They are
	// config-derived for the SAME reason as VertexModel: the resolved per-session lane is not
	// available at provision/Set time (it rides on EngineTask, at RunTask time), and the auth-proxy
	// must be rendered HEALTHY then — an empty CLOUD_ML_REGION makes the proxy fail to resolve its
	// upstream and crash-loop. VertexRegion is the engine's region form ("global", a multi-region,
	// or a regional location, e.g. "us-east5"); it feeds the proxy's upstream-host derivation.
	// VertexProject pins the proxy's request filter to one project (optional). Both are non-secret
	// ROUTING facts, never credentials. normalize requires VertexRegion whenever VertexModel is set.
	VertexRegion  string
	VertexProject string
}

// namePrefixRe bounds the prefix so derived Kubernetes object names ("<prefix>-sb-<32 hex>")
// are valid DNS-1123 labels and match the deploy modules' name_prefix validation.
var namePrefixRe = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$`)

// sandboxImageRe requires a digest-pinned image reference: a non-empty repository part with NO
// embedded "@" (so a malformed double-digest "repo@sha256:…@sha256:…" is rejected at construction,
// not deferred to a confusing kubelet pull error), then a single "@sha256:" digest of 64 lowercase
// hex at the end. It rejects a tag-only ("repo:tag") reference — only the digest content-addresses
// the bytes the kubelet runs. A ref MAY carry both a tag and a digest ("repo:tag@sha256:…"); the
// digest is always last, so anchoring it at the end is sufficient.
var sandboxImageRe = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

// gcpProjectRe bounds a GCP project id (6-30 chars: a lowercase letter, then lowercase
// letters/digits/hyphens, no trailing hyphen). The Vertex lane interpolates the task's
// ANTHROPIC_VERTEX_PROJECT_ID into the engine's env in engineRunScript, so validating the charset
// here is the shell-injection guard (it is a routing fact, not a credential, but still untrusted input).
var gcpProjectRe = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// vertexRegionRe bounds the engine's CLOUD_ML_REGION to GCP's location grammar plus the literal
// "global" (the location-independent endpoint). Like gcpProjectRe it is the shell-injection guard for
// the value engineRunScript interpolates into the engine env.
var vertexRegionRe = regexp.MustCompile(`^(global|[a-z]+-[a-z]+[0-9]+)$`)

// vertexModelRe bounds a Vertex publisher model id to the "@"-date form GCP serves
// ("<model>@YYYYMMDD" or "<model>@latest"), e.g. "claude-haiku-4-5@20251001". The "@" is
// mandatory: it both distinguishes a Vertex id from the Anthropic-API "-"-snapshot form (a
// fat-fingered API id has no "@" and is rejected) and, with the strict charset, keeps the value
// shell-safe when engineRunScript interpolates it into the engine's ANTHROPIC_MODEL env.
var vertexModelRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*@([0-9]{8}|latest)$`)

// normalize applies defaults and validates. It returns the effective config so New does not
// mutate the caller's value.
func (c Config) normalize() (Config, error) {
	if c.NamePrefix == "" {
		c.NamePrefix = DefaultNamePrefix
	}
	if c.RuntimeClass == "" {
		c.RuntimeClass = DefaultRuntimeClass
	}
	if c.NodePool == "" {
		c.NodePool = c.NamePrefix + "-sandbox"
	}
	if c.Workdir == "" {
		c.Workdir = DefaultWorkdir
	}
	if c.ProjectID == "" {
		return Config{}, errors.New("cloudgcp: Config.ProjectID is required")
	}
	if c.Location == "" {
		return Config{}, errors.New("cloudgcp: Config.Location is required")
	}
	if c.Cluster == "" {
		return Config{}, errors.New("cloudgcp: Config.Cluster is required")
	}
	if !namePrefixRe.MatchString(c.NamePrefix) {
		return Config{}, errors.New("cloudgcp: Config.NamePrefix must be 1-19 chars, lowercase, start with a letter, no trailing hyphen")
	}
	c.SandboxImage = strings.TrimSpace(c.SandboxImage)
	if c.SandboxImage == "" {
		return Config{}, errors.New("cloudgcp: Config.SandboxImage is required — the digest-pinned signed sandbox base image (…@sha256:…); build/sign it with .github/workflows/sandbox-image-release.yml and verify with scripts/verify-sandbox-image.sh")
	}
	if !sandboxImageRe.MatchString(c.SandboxImage) {
		return Config{}, fmt.Errorf("cloudgcp: Config.SandboxImage must be digest-pinned (…@sha256:<64 hex>), not tag-only — a tag is mutable and is not what the kubelet content-addresses; got %q", c.SandboxImage)
	}
	c.AnthropicModel = strings.TrimSpace(c.AnthropicModel)
	if err := c.normalizeVertex(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// normalizeVertex trims + validates the Vertex-lane fields (VertexModel, AuthProxyImage) in place on
// the receiver pointer. Split out of normalize so the per-field error reasoning lives together and
// normalize stays under the cyclomatic-complexity gate.
func (c *Config) normalizeVertex() error {
	c.VertexModel = strings.TrimSpace(c.VertexModel)
	if c.VertexModel != "" && !vertexModelRe.MatchString(c.VertexModel) {
		return fmt.Errorf("cloudgcp: Config.VertexModel %q must be a Vertex publisher model id in the \"@\"-date form (e.g. \"claude-haiku-4-5@20251001\" or \"<id>@latest\"), not the Anthropic-API \"-\"-snapshot form", c.VertexModel)
	}
	c.AuthProxyImage = strings.TrimSpace(c.AuthProxyImage)
	if c.AuthProxyImage != "" && !sandboxImageRe.MatchString(c.AuthProxyImage) {
		return fmt.Errorf("cloudgcp: Config.AuthProxyImage must be digest-pinned (…@sha256:<64 hex>), not tag-only — a tag is mutable and is not what the kubelet content-addresses; got %q", c.AuthProxyImage)
	}
	// A provider configured for the Vertex lane (VertexModel set) MUST also carry the auth-proxy
	// image — a Vertex session reaches the model only THROUGH the per-session auth-proxy (it attaches
	// the minted Vertex bearer; the engine sends no Authorization itself). Fail closed at
	// construction rather than provision a Vertex session with no credential-attaching gateway.
	if c.VertexModel != "" && c.AuthProxyImage == "" {
		return errors.New("cloudgcp: Config.AuthProxyImage is required when VertexModel is set (the Vertex lane reaches the model only through the per-session auth-proxy) — supply the digest-pinned signed image (…@sha256:…); build/sign it with .github/workflows/auth-proxy-image-release.yml and verify with scripts/verify-auth-proxy-image.sh")
	}
	c.VertexRegion = strings.TrimSpace(c.VertexRegion)
	c.VertexProject = strings.TrimSpace(c.VertexProject)
	// The auth-proxy derives its upstream Vertex host from CLOUD_ML_REGION (=VertexRegion) and
	// crash-loops on an empty value, so a Vertex-configured provider MUST carry the region — fail
	// closed at construction rather than render a proxy that cannot start.
	if c.VertexModel != "" && c.VertexRegion == "" {
		return errors.New("cloudgcp: Config.VertexRegion is required when VertexModel is set (the auth-proxy derives its Vertex upstream host from it) — set it to \"global\", a multi-region, or a regional location (e.g. \"us-east5\")")
	}
	return nil
}

// vertexConfigured reports whether this provider is configured for the Vertex lane — the
// config-derived lane gate the per-session renderers use because the resolved inference LANE is not
// available at provision/Set time (it rides on EngineTask, at RunTask time; see Config.VertexModel).
// normalize guarantees VertexModel ⇒ AuthProxyImage, so a true result means both the model pin and
// the auth-proxy image are present.
func (c Config) vertexConfigured() bool { return c.VertexModel != "" }
