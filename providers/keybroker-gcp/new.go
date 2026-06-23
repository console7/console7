package keybrokergcp

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
)

// New constructs the production KMS-backed CA, dialing Cloud KMS. Credentials resolve from
// Application Default Credentials (GKE Workload Identity in deployment) — no key file. It fetches the
// key version's public key once and pins it as the EC-P256 trust anchor (failing closed if the key is
// not EC-P256). Pass option.ClientOptions for tests/integration; production passes none. Call Close
// at shutdown to release the client.
func New(ctx context.Context, cfg Config, opts ...option.ClientOption) (*Provider, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("keybrokergcp: dial Cloud KMS: %w", err)
	}
	p, err := newWithPorts(ctx, &kmsAsymmetricGCP{client: client, keyVersionName: cfg.KeyVersionName})
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	p.closer = client
	return p, nil
}

// NewWithPorts assembles a Provider from an explicit signer port — the seam tests and the conformance
// harness use to wire the in-process fake. It resolves and pins the anchor through the port, exactly
// as New does, so the fake exercises the same Sign->Root round-trip.
func NewWithPorts(ctx context.Context, signer kmsAsymmetricSigner) (*Provider, error) {
	return newWithPorts(ctx, signer)
}

func newWithPorts(ctx context.Context, signer kmsAsymmetricSigner) (*Provider, error) {
	pemStr, err := signer.PublicKeyPEM(ctx)
	if err != nil {
		return nil, fmt.Errorf("keybrokergcp: fetch CA public key: %w", err)
	}
	anchor, err := parseECP256PublicKeyPEM(pemStr)
	if err != nil {
		return nil, err
	}
	return &Provider{kms: signer, anchor: anchor}, nil
}

// Close releases the underlying KMS client New opened. It is a no-op for a Provider built with
// NewWithPorts (the fake leaves closer nil). Safe to call once at keybroker shutdown.
func (p *Provider) Close() error {
	if p.closer == nil {
		return nil
	}
	return p.closer.Close()
}
