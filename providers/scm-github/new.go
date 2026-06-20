package scmgithub

import (
	"fmt"
	"net/http"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
)

// New constructs the production Provider for a registered GitHub App. The App private key comes
// from cfg (sourced from the adopter secret store, never a committed file — see README). It builds
// an App-JWT transport (ghinstallation) and an App-authenticated go-github client; one ghApp
// adapter satisfies both provider ports. The same adapter mints repository-scoped, permission-
// narrowed installation tokens and opens pull requests as the installation.
func New(cfg Config) (*Provider, error) {
	cfg, key, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	// Fail fast on a Config.Permissions outside the least-privilege allowlist (key or level),
	// rather than surfacing it only on the first mint.
	if _, err := toInstallationPermissions(cfg.Permissions); err != nil {
		return nil, err
	}

	appsTransport := ghinstallation.NewAppsTransportFromPrivateKey(http.DefaultTransport, cfg.AppID, key)
	if cfg.BaseURL != "" {
		// Point App-JWT token minting at the GitHub Enterprise Server host too (best-effort GHES;
		// the github.com default needs no override).
		appsTransport.BaseURL = cfg.BaseURL
	}
	appClient, err := newGitHubClient(appsTransport, cfg.BaseURL)
	if err != nil {
		return nil, err
	}

	adapter := &ghApp{
		appsTransport: appsTransport,
		appClient:     appClient,
		fixedInstall:  cfg.InstallationID,
		perms:         cfg.Permissions,
		baseURL:       cfg.BaseURL,
	}
	p := NewWithPorts(adapter, adapter, cfg.TTL, cfg.ProtectedBranches...)
	// Use the configured (validated) least-privilege permission set for minting.
	p.perms = cfg.Permissions
	return p, nil
}

// newGitHubClient builds a go-github client over the given RoundTripper (an App-JWT or
// installation transport), pointing it at GitHub Enterprise Server when baseURL is set.
func newGitHubClient(rt http.RoundTripper, baseURL string) (*github.Client, error) {
	opts := []github.ClientOptionsFunc{github.WithTransport(rt)}
	if baseURL != "" {
		opts = append(opts, github.WithEnterpriseURLs(baseURL, baseURL))
	}
	c, err := github.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("scmgithub: building GitHub client: %w", err)
	}
	return c, nil
}
