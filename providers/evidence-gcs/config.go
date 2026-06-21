package evidencegcs

import (
	"errors"
	"regexp"
)

// DefaultObjectPrefix is the object-name prefix used when Config.ObjectPrefix is empty. Records
// are stored at "<prefix>/<zero-padded-sequence>", so the prefix namespaces the evidence log
// within its bucket and keeps Count/list scoped to it.
const DefaultObjectPrefix = "records"

// Config configures the production Store (New). The bucket and the workload identity that may
// write to it are provisioned by deploy/gcp/modules/evidence; Bucket is that module's
// bucket_name output.
type Config struct {
	// Bucket is the GCS bucket that holds the evidence log. It MUST be a distinct bucket from
	// the operational database (control-plane/evidence.Store SECURITY note; DESIGN.md §6), with
	// a retention policy (and, in production, a bucket lock) enforcing immutability.
	Bucket string
	// ObjectPrefix prefixes every record object. Defaults to DefaultObjectPrefix. Two Sinks
	// sharing one bucket MUST use distinct prefixes — each prefix is an independent append-only
	// log, and Count/hydration are scoped to it.
	ObjectPrefix string
}

// objectPrefixRe bounds the prefix to a GCS-safe, single-segment name (no slashes, no leading
// dot) so the derived object name "<prefix>/<sequence>" is well-formed and the prefix cannot
// escape its namespace.
var objectPrefixRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// normalize applies defaults and validates. It returns the effective config so New does not
// mutate the caller's value.
func (c Config) normalize() (Config, error) {
	if c.ObjectPrefix == "" {
		c.ObjectPrefix = DefaultObjectPrefix
	}
	if c.Bucket == "" {
		return Config{}, errors.New("evidencegcs: Config.Bucket is required")
	}
	if !objectPrefixRe.MatchString(c.ObjectPrefix) {
		return Config{}, errors.New("evidencegcs: Config.ObjectPrefix must be 1-63 chars of [a-z0-9_-], starting alphanumeric (no slashes)")
	}
	return c, nil
}
