package secretsgcp

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// smStore is the real SecretStore: per-subject secrets in GCP Secret Manager. Replication is
// user-managed and pinned to one region, keeping payloads in-region (no egress of adopter
// data). Labels carry no PII. The workload SA's least-privilege role (deploy/gcp/modules/
// secrets) grants exactly create / versions.add / versions.access / secrets.delete at PROJECT
// scope — that narrow verb set (no get, no list, no IAM-policy verbs) is the boundary. The
// "<prefix>-sub-*" naming is a provider-side convention (and a future IAM-condition hardening
// target), not a current IAM restriction: secrets.create is evaluated at the project parent,
// so a name-prefix condition would deny every create.
type smStore struct {
	client    *secretmanager.Client
	projectID string
	region    string
}

var _ SecretStore = (*smStore)(nil)

// managedLabels tag every secret for lifecycle/cost queries. They are PII-free.
var managedLabels = map[string]string{
	"managed-by": "console7",
	"component":  "secrets-gcp",
	"purpose":    "subscription-token",
}

func (s *smStore) parent() string        { return "projects/" + s.projectID }
func (s *smStore) name(id string) string { return s.parent() + "/secrets/" + id }

// Put ensures the per-subject secret exists (creating it with region-pinned replication on
// first use) and adds a new version carrying payload — a re-login's version becomes "latest".
// Superseded versions are left in place (no versions.destroy granted) and are shredded
// together with the secret on revoke; see the SecretStore port doc.
func (s *smStore) Put(ctx context.Context, secretID string, payload []byte) (string, error) {
	_, err := s.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   s.parent(),
		SecretId: secretID,
		Secret: &secretmanagerpb.Secret{
			Labels: managedLabels,
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_UserManaged_{
					UserManaged: &secretmanagerpb.Replication_UserManaged{
						Replicas: []*secretmanagerpb.Replication_UserManaged_Replica{
							{Location: s.region},
						},
					},
				},
			},
		},
	})
	// AlreadyExists is the steady state after the first store; only other errors are fatal.
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return "", fmt.Errorf("secretsgcp: create secret failed: %w", err)
	}

	ver, err := s.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  s.name(secretID),
		Payload: &secretmanagerpb.SecretPayload{Data: payload},
	})
	if err != nil {
		return "", fmt.Errorf("secretsgcp: add secret version failed: %w", err)
	}
	return ver.GetName(), nil
}

// Get accesses the latest version's payload. A missing secret (or one with no live version) is
// reported as not-found, not an error, so the caller distinguishes "no stored token" from a
// backend failure.
func (s *smStore) Get(ctx context.Context, secretID string) ([]byte, bool, error) {
	resp, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: s.name(secretID) + "/versions/latest",
	})
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound, codes.FailedPrecondition:
			// NotFound: no such secret/version. FailedPrecondition: the latest version is
			// destroyed/disabled — no readable material, treated the same as absent.
			return nil, false, nil
		default:
			return nil, false, fmt.Errorf("secretsgcp: access secret version failed: %w", err)
		}
	}
	return resp.GetPayload().GetData(), true, nil
}

// Destroy deletes the whole secret (and thus every version), crypto-shredding the wrapped DEK.
// Deleting an absent secret is success — RevokeSubject is idempotent.
func (s *smStore) Destroy(ctx context.Context, secretID string) error {
	err := s.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: s.name(secretID),
	})
	if err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("secretsgcp: delete secret failed: %w", err)
	}
	return nil
}
