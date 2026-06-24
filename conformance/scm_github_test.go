package conformance

import (
	"testing"
	"time"

	scmgithub "github.com/console7/console7/providers/scm-github"
	"github.com/console7/console7/sdk/testkit"
)

// This run asserts the GitHub reference SCMProvider upholds the same two SECURITY contracts the
// devkit double (MemSCM) does — but exercising providers/scm-github's own logic. The provider is
// wired with its in-memory fakes (a GitHub App-auth stand-in and a PR-opener stand-in), so the
// contract checks run with no GitHub App and no network. The GitHub-specific invariants
// (least-privilege scoping, no durable token leaving the provider, fail-closed on a mint/open
// error) are proven by the provider's own white-box tests (providers/scm-github/provider_test.go);
// a green run here asserts the interface-observable behaviour only (sdk/testkit check doc;
// DESIGN.md §2.1/§2.3/§7).
func scmGitHubUnderTest() testkit.ProviderUnderTest {
	return testkit.ProviderUnderTest{
		SCM: scmgithub.NewWithPorts(scmgithub.NewInMemoryAppAuth(), scmgithub.NewInMemoryPullRequests(), scmgithub.NewInMemoryGitTransport(), 15*time.Minute),
	}
}

// TestSCMGitHubConformance runs every SCMProvider contract against the GitHub reference provider
// (faked) and requires that none fail. The devkit run lives in TestHarnessWiring; this is the
// parallel run proving the real provider's logic conforms too.
func TestSCMGitHubConformance(t *testing.T) {
	res := testkit.Run(scmGitHubUnderTest())
	if len(res.Checked) == 0 {
		t.Fatal("expected the two SCMProvider contracts to be checked, got none")
	}
	if len(res.Failed) != 0 {
		t.Fatalf("scm-github conformance run reported %d contract failure(s): %v", len(res.Failed), res.Failed)
	}
}
