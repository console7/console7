package scmgithub

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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
	// Resolve + validate the SCM host BEFORE wiring the transport, so a cleartext or
	// credential-bearing BaseURL fails closed and never reaches the App-JWT transport.
	host, err := expectedHostFromBaseURL(cfg.BaseURL)
	if err != nil {
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
	// gitCLI is the real git-over-HTTPS transport for the control-plane push→PR bridge (shell-out,
	// zero new dependency); the minted installation token reaches it in-env, never argv.
	p := NewWithPorts(adapter, adapter, gitCLI{}, cfg.TTL, cfg.ProtectedBranches...)
	// Use the configured (validated) granted-permission ceiling for minting.
	p.perms = cfg.Permissions
	// Scope the provider to the SCM host it actually talks to, so a RepoRef for a different host
	// fails closed rather than minting a homonym on this endpoint (host resolved+validated above).
	p.expectedHost = host
	return p, nil
}

// expectedHostFromBaseURL returns the SCM host the provider serves: github.com when BaseURL is
// unset, otherwise the host of the GitHub Enterprise Server API base.
func expectedHostFromBaseURL(baseURL string) (string, error) {
	if baseURL == "" {
		return DefaultExpectedHost, nil
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		// Do not echo the raw value: a malformed URL may still carry userinfo a caller logs.
		return "", errors.New("scmgithub: Config.BaseURL is not a valid URL with a host")
	}
	// Fail closed on cleartext: ghinstallation POSTs the App JWT to this base and receives the
	// installation token back, so an http:// base would expose both on the wire. Enforce https to
	// match the inference providers (inference-anthropic/-vertex reject non-https identically), and
	// reject embedded userinfo so a credential cannot ride in the base URL.
	if u.User != nil {
		return "", errors.New("scmgithub: Config.BaseURL must not embed userinfo credentials")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("scmgithub: Config.BaseURL %q must use https", u.Redacted())
	}
	return u.Host, nil
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
