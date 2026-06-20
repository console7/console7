//go:build gcp_integration

// Opt-in live integration test against a real GCP project (e.g. console7-dev). It is NEVER
// part of the CI gate — it compiles only under `-tags gcp_integration` and skips unless the
// environment names a project, KEK, and region. It exercises the REAL Cloud KMS wrap/unwrap
// and Secret Manager create/add-version/access/delete paths; the Injector is the devkit
// registry (the data-plane sandbox is the one piece still deferred).
//
// Run:
//
//	C7_GCP_PROJECT=console7-dev \
//	C7_KEK_RESOURCE=projects/console7-dev/locations/us-east4/keyRings/console7-secrets/cryptoKeys/console7-secrets-kek \
//	C7_GCP_REGION=us-east4 \
//	go test -tags gcp_integration -run TestIntegration ./providers/secrets-gcp/...
//
// Credentials resolve from Application Default Credentials (e.g. `gcloud auth
// application-default login`, or Workload Identity Federation in CD).
package secretsgcp

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"

	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

func TestIntegration_StoreInjectRevoke(t *testing.T) {
	project := os.Getenv("C7_GCP_PROJECT")
	kekResource := os.Getenv("C7_KEK_RESOURCE")
	region := os.Getenv("C7_GCP_REGION")
	if project == "" || kekResource == "" || region == "" {
		t.Skip("set C7_GCP_PROJECT, C7_KEK_RESOURCE, C7_GCP_REGION to run the live integration test")
	}

	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		t.Fatalf("dial KMS: %v", err)
	}
	defer kmsClient.Close()
	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		t.Fatalf("dial Secret Manager: %v", err)
	}
	defer smClient.Close()

	reg := devkit.NewSandboxRegistry()
	p := NewWithPorts(
		&kmsKEK{client: kmsClient, keyName: kekResource},
		&smStore{client: smClient, projectID: project, region: region},
		reg,
		"console7",
		nil,
	)

	// A unique per-run subject so concurrent/repeated runs do not collide; always revoke.
	subject := interfaces.Subject("itest-" + randHex(8) + "@example.test")
	defer func() {
		if err := p.RevokeSubject(ctx, subject); err != nil {
			t.Errorf("cleanup RevokeSubject: %v", err)
		}
	}()

	token := []byte("integration-subscription-token-" + randHex(4))
	if err := p.StoreSubscriptionToken(ctx, interfaces.SubscriptionToken{Subject: subject, Token: token}); err != nil {
		t.Fatalf("StoreSubscriptionToken: %v", err)
	}

	box := reg.Provision(subject, "s1")
	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: subject, SessionID: "s1", Sandbox: box, Attended: true, Beneficiaries: 1,
	}); err != nil {
		t.Fatalf("InjectSubscriptionToken: %v", err)
	}
	got, ok := reg.Injected(box)
	if !ok || !bytes.Equal(got, token) {
		t.Fatalf("roundtrip mismatch: ok=%v got=%q want=%q", ok, got, token)
	}

	if err := p.RevokeSubject(ctx, subject); err != nil {
		t.Fatalf("RevokeSubject: %v", err)
	}
	// Secret Manager deletes are not always instantaneous to reads; allow a brief settle.
	time.Sleep(2 * time.Second)
	box2 := reg.Provision(subject, "s2")
	if err := p.InjectSubscriptionToken(ctx, interfaces.SubscriptionInjection{
		Subject: subject, SessionID: "s2", Sandbox: box2, Attended: true, Beneficiaries: 1,
	}); err == nil {
		t.Error("injection succeeded after revocation — material was recoverable")
	}
}
