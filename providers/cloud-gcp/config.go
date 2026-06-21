package cloudgcp

import (
	"errors"
	"regexp"
)

// DefaultNamePrefix matches deploy/gcp/modules/networking + modules/gke name_prefix default,
// so the sandbox resources this provider names line up with the cluster/node-pool/tag those
// modules provision.
const DefaultNamePrefix = "console7"

// DefaultRuntimeClass is the Kubernetes RuntimeClass GKE Sandbox (gVisor) registers.
const DefaultRuntimeClass = "gvisor"

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
	// output). The pool runs WITHOUT Workload Identity, which is the authoritative metadata
	// block (a sandbox pod gets no node-local metadata credential). Defaults to
	// "<NamePrefix>-sandbox".
	NodePool string
	// RuntimeClass is the gVisor RuntimeClass name. Defaults to DefaultRuntimeClass.
	RuntimeClass string
}

// namePrefixRe bounds the prefix so derived Kubernetes object names ("<prefix>-sb-<12 hex>")
// are valid DNS-1123 labels and match the deploy modules' name_prefix validation.
var namePrefixRe = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$`)

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
	return c, nil
}
