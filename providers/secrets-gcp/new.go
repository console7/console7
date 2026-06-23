package secretsgcp

import (
	"context"
	"fmt"
	"io"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	kms "cloud.google.com/go/kms/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"google.golang.org/api/option"
)

// New constructs the production Provider, dialing Cloud KMS and Secret Manager. Credentials
// resolve from Application Default Credentials (GKE Workload Identity in deployment) — no key
// file. Pass option.ClientOptions for tests/integration (e.g. a fake endpoint or an explicit
// credential); production passes none.
//
// The Injector starts wired fail-closed (denyInjector): this secrets New refuses to deliver into
// an unverified sandbox until the data-plane path is wired. The REAL Injector exists — the
// providers/cloud-gcp Provider satisfies this seam (Owns/DeliverIfOwned: ownership-checked delivery
// into the pod's memory volume, B5) — and wiring it in is the ORCHESTRATOR's job (it holds both
// providers): call SetInjector(cloud) on the returned Provider (or build via NewWithPorts to inject
// at construction). Until that wiring lands, this convenience constructor stays fail-closed.
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

	// Wire the inference-lane token minter only when a workload SA is configured: New dials IAM
	// Credentials and impersonates that SA (self-impersonation — it holds tokenCreator on itself) to
	// mint the short-lived Vertex bearer. When WorkloadSAEmail is empty the fail-closed denyMinter is
	// kept, so a deployment that never uses the Vertex lane stays minter-free and InjectInferenceCredential
	// refuses rather than running unauthenticated.
	if cfg.WorkloadSAEmail != "" {
		credClient, cerr := credentials.NewIamCredentialsClient(ctx, opts...)
		if cerr != nil {
			_ = p.Close()
			return nil, fmt.Errorf("secretsgcp: dial IAM Credentials: %w", cerr)
		}
		p.SetAccessTokenMinter(&iamCredentialsMinter{
			client: credClient,
			saName: "projects/-/serviceAccounts/" + cfg.WorkloadSAEmail,
		})
		p.closers = append(p.closers, credClient)
	}
	return p, nil
}
