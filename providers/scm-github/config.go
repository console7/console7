package scmgithub

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

// Config configures the production provider (New). The GitHub App is registered out-of-band by
// the adopter (see README's setup checklist); this carries the App ID, the App private key, and
// either a fixed installation or instructions to look the installation up per-repo.
type Config struct {
	// AppID is the GitHub App's numeric identifier.
	AppID int64
	// PrivateKeyPEM is the App's RSA private key in PEM form (PKCS#1 or PKCS#8). It is the App's
	// signing key — it MUST come from the adopter secret store (the SecretsProvider seam), NEVER
	// a committed file. New parses it once and holds the parsed key in memory; the PEM is not
	// retained.
	PrivateKeyPEM []byte
	// InstallationID, if non-zero, is the fixed installation to mint tokens against. If zero, the
	// provider resolves the installation per-repo (Apps.FindRepositoryInstallation), so one App
	// can serve several repos.
	InstallationID int64
	// BaseURL overrides the GitHub REST API base for GitHub Enterprise Server (e.g.
	// "https://ghe.example.com/api/v3/"). Empty targets github.com.
	BaseURL string
	// Permissions overrides the least-privilege installation-token permission set. Empty defaults
	// to DefaultPermissions. Keys must be within the adapter's allowlist (contents, pull_requests,
	// metadata); anything else is rejected rather than silently granted.
	Permissions map[string]string
	// ProtectedBranches names branches — beyond the always-protected main/master — a working
	// credential must never be scoped to.
	ProtectedBranches []string
	// TTL bounds working-credential lifetime; the effective expiry is capped further by the GitHub
	// token expiry and the session deadline. Defaults to DefaultTTL.
	TTL time.Duration
}

// normalize validates the config and returns the effective config plus the parsed App private
// key, so New does not mutate the caller's value and fails fast on a bad key rather than at the
// first mint.
func (c Config) normalize() (Config, *rsa.PrivateKey, error) {
	if c.AppID <= 0 {
		return Config{}, nil, errors.New("scmgithub: Config.AppID is required")
	}
	if len(c.PrivateKeyPEM) == 0 {
		return Config{}, nil, errors.New("scmgithub: Config.PrivateKeyPEM is required (from the adopter secret store, never a committed file)")
	}
	key, err := parseRSAPrivateKey(c.PrivateKeyPEM)
	if err != nil {
		return Config{}, nil, err
	}
	if len(c.Permissions) == 0 {
		c.Permissions = DefaultPermissions
	}
	if c.TTL <= 0 {
		c.TTL = DefaultTTL
	}
	return c, key, nil
}

// parseRSAPrivateKey decodes a PEM-encoded RSA private key in PKCS#1 or PKCS#8 form.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("scmgithub: Config.PrivateKeyPEM is not valid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("scmgithub: Config.PrivateKeyPEM is not a PKCS#1 or PKCS#8 private key")
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("scmgithub: Config.PrivateKeyPEM is not an RSA key")
	}
	return key, nil
}
