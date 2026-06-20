package secretsgcp

import (
	"errors"
	"regexp"
)

// DefaultSecretPrefix is the resource-name prefix used when Config.SecretPrefix is empty. It
// matches deploy/gcp/modules/secrets' name_prefix default so the provider's secret IDs fall
// under the IAM condition that scopes the workload SA to "<prefix>-sub-*".
const DefaultSecretPrefix = "console7"

// Config configures the production provider (New). The KEK and the workload identity are
// provisioned by deploy/gcp/modules/secrets; KEKResourceName is that module's
// kms_crypto_key_id output.
type Config struct {
	// ProjectID is the adopter's GCP project that owns the Secret Manager secrets.
	ProjectID string
	// KEKResourceName is the full Cloud KMS crypto-key resource id used for provider-side
	// envelope encryption, e.g.
	// "projects/<p>/locations/<r>/keyRings/<kr>/cryptoKeys/<prefix>-secrets-kek".
	KEKResourceName string
	// SecretPrefix prefixes every managed secret ID. Defaults to DefaultSecretPrefix. It must
	// match the name_prefix the deploy module's IAM condition scopes to.
	SecretPrefix string
	// Region pins Secret Manager user-managed replication to one location, keeping payloads
	// in-region (no egress of adopter data). It MUST match the KMS key ring's location.
	Region string
}

// secretPrefixRe bounds the prefix so a derived secret ID ("<prefix>-sub-<64 hex>") is a
// valid Secret Manager secret ID ([a-zA-Z0-9_-]{1,255}) and matches the deploy module's
// name_prefix validation.
var secretPrefixRe = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$`)

// normalize applies defaults and validates. It returns the effective config so New does not
// mutate the caller's value.
func (c Config) normalize() (Config, error) {
	if c.SecretPrefix == "" {
		c.SecretPrefix = DefaultSecretPrefix
	}
	if c.ProjectID == "" {
		return Config{}, errors.New("secretsgcp: Config.ProjectID is required")
	}
	if c.KEKResourceName == "" {
		return Config{}, errors.New("secretsgcp: Config.KEKResourceName is required")
	}
	if c.Region == "" {
		return Config{}, errors.New("secretsgcp: Config.Region is required (pins Secret Manager replication in-region)")
	}
	if !secretPrefixRe.MatchString(c.SecretPrefix) {
		return Config{}, errors.New("secretsgcp: Config.SecretPrefix must be 1-19 chars, lowercase, start with a letter, no trailing hyphen")
	}
	return c, nil
}
