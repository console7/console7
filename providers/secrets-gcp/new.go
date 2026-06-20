package secretsgcp

import (
	"context"
	"fmt"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"google.golang.org/api/option"
)

// New constructs the production Provider, dialing Cloud KMS and Secret Manager. Credentials
// resolve from Application Default Credentials (GKE Workload Identity in deployment) — no key
// file. Pass option.ClientOptions for tests/integration (e.g. a fake endpoint or an explicit
// credential); production passes none.
//
// The Injector is wired fail-closed (denyInjector): until the data-plane sandbox exists,
// InjectSubscriptionToken refuses rather than delivering into an unverified sandbox. When the
// sandbox PR lands, the orchestrator builds the provider via NewWithPorts with the real
// Injector instead.
//
// Call Close at shutdown to release the clients.
func New(ctx context.Context, cfg Config, opts ...option.ClientOption) (*Provider, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}

	kmsClient, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("secretsgcp: dial Cloud KMS: %w", err)
	}
	smClient, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		// Close the KMS client we already opened so New does not leak it on partial failure.
		_ = kmsClient.Close()
		return nil, fmt.Errorf("secretsgcp: dial Secret Manager: %w", err)
	}

	p := NewWithPorts(
		&kmsKEK{client: kmsClient, keyName: cfg.KEKResourceName},
		&smStore{client: smClient, projectID: cfg.ProjectID, region: cfg.Region},
		denyInjector{},
		cfg.SecretPrefix,
		nil,
	)
	p.closers = []io.Closer{kmsClient, smClient}
	return p, nil
}
