package secretsgcp

import (
	"context"
	"fmt"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// iamCredentialsMinter is the production AccessTokenMinter: it mints a short-lived GCP OAuth2 access
// token for the workload service account via IAM Credentials GenerateAccessToken. The control plane
// runs AS the workload SA (GKE Workload Identity); the SA holds roles/iam.serviceAccountTokenCreator
// on ITSELF (deploy/gcp/modules/secrets), so this downscopes its own identity to a short-lived,
// scope-capped token the sandbox uses for Vertex — the sandbox itself never reaches the metadata
// server. The token is the only thing that crosses the AccessTokenMinter boundary; the provider
// delivers it straight into the owning sandbox and never returns it to the control plane.
type iamCredentialsMinter struct {
	client *credentials.IamCredentialsClient
	// saName is the impersonation target in GenerateAccessToken's required form
	// "projects/-/serviceAccounts/<email>" (the "-" wildcard is mandatory).
	saName string
}

var _ AccessTokenMinter = (*iamCredentialsMinter)(nil)

// MintAccessToken mints an access token for the workload SA, scoped to scopes, requesting `lifetime`
// (GenerateAccessToken caps the lifetime to 3600s itself; the provider has already capped to the
// session deadline). It returns the token bytes and the API-reported absolute expiry. The token
// value is never logged or wrapped into an error.
func (m *iamCredentialsMinter) MintAccessToken(ctx context.Context, scopes []string, lifetime time.Duration) ([]byte, time.Time, error) {
	resp, err := m.client.GenerateAccessToken(ctx, &credentialspb.GenerateAccessTokenRequest{
		Name:     m.saName,
		Scope:    scopes,
		Lifetime: durationpb.New(lifetime),
	})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("secretsgcp: GenerateAccessToken: %w", err)
	}
	tok := resp.GetAccessToken()
	if tok == "" {
		return nil, time.Time{}, fmt.Errorf("secretsgcp: GenerateAccessToken returned an empty token")
	}
	return []byte(tok), resp.GetExpireTime().AsTime(), nil
}
