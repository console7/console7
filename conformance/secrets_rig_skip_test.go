package conformance

import (
	"testing"

	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/testkit"
)

// TestSecretsInjection_SkippedWithoutRig pins the fix for the spurious-PASS gap: when a
// SecretsProvider is supplied but the optional SecretsRig is NOT, the three injection security
// contracts (which need a real owned sandbox to exercise the attended/beneficiary/ownership gate)
// must be reported as SKIPPED — never as Checked/passed. A provider that merely rejects unknown
// handles must not earn a green certificate for a gate that was never run.
func TestSecretsInjection_SkippedWithoutRig(t *testing.T) {
	reg := devkit.NewSandboxRegistry()
	res := testkit.Run(testkit.ProviderUnderTest{
		Secrets: devkit.NewMemSecrets(reg),
		// SecretsRig deliberately omitted.
	})

	injection := map[string]bool{
		"InjectSubscriptionToken":   true,
		"InjectOrgCredential":       true,
		"InjectInferenceCredential": true,
	}
	skipped := map[string]bool{}
	for _, c := range res.Skipped {
		if c.Interface == "SecretsProvider" {
			skipped[c.Method] = true
		}
	}
	for _, c := range res.Checked {
		if c.Interface == "SecretsProvider" && injection[c.Method] {
			t.Errorf("injection contract %s ran (Checked) without a rig — must be skipped, not passed", c.Method)
		}
	}
	for m := range injection {
		if !skipped[m] {
			t.Errorf("injection contract %s not reported as Skipped without a rig", m)
		}
	}
}
