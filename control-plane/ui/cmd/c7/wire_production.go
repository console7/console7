//go:build c7_live

package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/console7/console7/control-plane/evidence"
	"github.com/console7/console7/control-plane/orchestrator"
	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	cloudgcp "github.com/console7/console7/providers/cloud-gcp"
	evidencegcs "github.com/console7/console7/providers/evidence-gcs"
	inferenceanthropic "github.com/console7/console7/providers/inference-anthropic"
	inferencevertex "github.com/console7/console7/providers/inference-vertex"
	keybrokergcp "github.com/console7/console7/providers/keybroker-gcp"
	scmgithub "github.com/console7/console7/providers/scm-github"
	secretsgcp "github.com/console7/console7/providers/secrets-gcp"
	"github.com/console7/console7/sdk/devkit"
	"github.com/console7/console7/sdk/interfaces"
)

const spineBanner = "PRODUCTION wiring (real GCP/GitHub/inference + KMS-backed keybroker CA + GCS WORM evidence). " +
	"RESIDUALS (Phase-1): SSO->NHI authn is a DEV assertion (no OIDC IdP provider yet) and PolicySoR is the fixed dev SoR — both tracked, not yet productionised."

// envReader collects every missing required variable so loadProdEnv fails closed with ONE actionable
// error rather than one-at-a-time.
type envReader struct{ missing []string }

func (e *envReader) req(name string) string {
	v := os.Getenv(name)
	if v == "" {
		e.missing = append(e.missing, name)
	}
	return v
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// prodEnv is the validated production configuration read from the environment.
type prodEnv struct {
	project, location, cluster, sandboxImage string
	kekResource, region, workloadSA          string
	ghAppID, ghInstall                       int64
	ghKey                                    []byte
	kmsKeyVersion, evidenceBucket            string
	inferenceKind                            string
}

// loadProdEnv reads + validates every required variable (and parses the GitHub App integers/key),
// failing closed with one error listing everything missing/malformed. Confined here so wireSpine
// stays a straight-line assembly.
func loadProdEnv() (*prodEnv, error) {
	e := &envReader{}
	p := &prodEnv{
		project:        e.req("C7_GKE_PROJECT"),
		location:       e.req("C7_GKE_LOCATION"),
		cluster:        e.req("C7_GKE_CLUSTER"),
		sandboxImage:   e.req("C7_SANDBOX_IMAGE"),
		kekResource:    e.req("C7_KEK_RESOURCE"),
		region:         e.req("C7_REGION"),
		workloadSA:     e.req("C7_WORKLOAD_SA_EMAIL"),
		kmsKeyVersion:  e.req("C7_KMS_KEY_VERSION"),
		evidenceBucket: e.req("C7_EVIDENCE_BUCKET"),
		inferenceKind:  e.req("C7_INFERENCE"), // "anthropic" | "vertex"
	}
	ghAppIDStr := e.req("C7_GH_APP_ID")
	ghInstallStr := e.req("C7_GH_INSTALLATION_ID")
	ghKeyFile := e.req("C7_GH_APP_KEY_FILE")
	if len(e.missing) > 0 {
		return nil, fmt.Errorf("missing required env: %s", strings.Join(e.missing, ", "))
	}

	var err error
	if p.ghAppID, err = strconv.ParseInt(ghAppIDStr, 10, 64); err != nil {
		return nil, fmt.Errorf("C7_GH_APP_ID is not an integer: %w", err)
	}
	if p.ghInstall, err = strconv.ParseInt(ghInstallStr, 10, 64); err != nil {
		return nil, fmt.Errorf("C7_GH_INSTALLATION_ID is not an integer: %w", err)
	}
	if p.ghKey, err = os.ReadFile(ghKeyFile); err != nil { // #nosec G304 -- operator-supplied path to the GitHub App key (PEM), not attacker input
		return nil, fmt.Errorf("read GitHub App key %q: %w", ghKeyFile, err)
	}
	return p, nil
}

// buildInference selects the inference backend from C7_INFERENCE and returns it together with the
// matching engine-model lane on the CloudProvider config (Anthropic "-"-snapshot vs Vertex "@"-form).
func buildInference(p *prodEnv) (interfaces.InferenceBackend, cloudgcp.Config, error) {
	cfg := cloudgcp.Config{ProjectID: p.project, Location: p.location, Cluster: p.cluster, SandboxImage: p.sandboxImage}
	switch p.inferenceKind {
	case "vertex":
		// "global" is the engine's location-independent endpoint, NOT a GCP regional location:
		// it fails inference-vertex's regional-host grammar guard (regionPattern). Select it via
		// Config.Global (which normalize() maps to GlobalHost + CLOUD_ML_REGION="global") rather
		// than threading "global" through Config.Region. Any other value stays the regional lane.
		vertexRegion := envOr("C7_VERTEX_REGION", p.region)
		vertexCfg := inferencevertex.Config{ProjectID: envOr("C7_VERTEX_PROJECT", p.project)}
		if vertexRegion == "global" {
			vertexCfg.Global = true
		} else {
			vertexCfg.Region = vertexRegion
		}
		inf, err := inferencevertex.New(vertexCfg)
		cfg.VertexModel = os.Getenv("C7_VERTEX_MODEL")
		return inf, cfg, err
	case "anthropic":
		inf, err := inferenceanthropic.New(inferenceanthropic.Config{OrgAPIBaseURL: os.Getenv("C7_ANTHROPIC_BASE_URL")})
		cfg.AnthropicModel = os.Getenv("C7_ANTHROPIC_MODEL")
		return inf, cfg, err
	default:
		return nil, cfg, fmt.Errorf("C7_INFERENCE must be \"anthropic\" or \"vertex\", got %q", p.inferenceKind)
	}
}

// inferenceAllowlist derives the egress allowlist from the inference backend ITSELF — the exact
// URL(s) it will resolve to at session time — so the operator never hand-matches an endpoint string
// (a drift footgun) and the prod build keeps every lane the dev spine had. Resolve is pure (no
// network, no credential), so calling it here is safe; it seeds the org-API URL and, if the backend
// serves it, the subscription URL. A backend that refuses a mode (e.g. Vertex refuses subscription)
// simply contributes nothing for it. The boundary stays authoritative — the orchestrator re-checks
// each session's resolved URL against this same set.
func inferenceAllowlist(ctx context.Context, inf interfaces.InferenceBackend) []string {
	var out []string
	seen := map[string]bool{}
	add := func(sel interfaces.InferenceSelection) {
		if ep, err := inf.Resolve(ctx, sel); err == nil && ep.URL != "" && !seen[ep.URL] {
			seen[ep.URL] = true
			out = append(out, ep.URL)
		}
	}
	add(interfaces.InferenceSelection{Mode: interfaces.ModeOrgAPI, Beneficiaries: 1})
	add(interfaces.InferenceSelection{Mode: interfaces.ModeSubscription, Attended: true, Beneficiaries: 1})
	return out
}

// wireSpine assembles the PRODUCTION orchestrator spine from the environment: the real GCP/GitHub/
// inference seams, the KMS-backed keybroker CA as the lineage trust root, and the GCS WORM evidence
// sink. It returns the SAME tuple as the dev spine, driving the identical ui.Launch surface.
//
// Build-tagged c7_live: compiled in CI (`go build -tags c7_live`) so it cannot bit-rot, but never RUN
// there — it needs a real tenancy (a live GKE cluster, KMS keys, a GitHub App). The clients it opens
// live for the process; c7 is a single-shot CLI that exits after one session, so they are reclaimed
// at exit (a long-running control plane would manage their lifecycles).
func wireSpine(repo interfaces.RepoRef, user string) (*orchestrator.Orchestrator, interfaces.AuthnToken, *evidence.Sink, error) {
	ctx := context.Background()
	p, err := loadProdEnv()
	if err != nil {
		return nil, "", nil, err
	}
	inference, cloudCfg, err := buildInference(p)
	if err != nil {
		return nil, "", nil, fmt.Errorf("inference backend (%s): %w", p.inferenceKind, err)
	}
	allowlist := inferenceAllowlist(ctx, inference)
	if len(allowlist) == 0 {
		return nil, "", nil, fmt.Errorf("inference backend (%s) resolved no endpoints to allow — check C7_INFERENCE and the model/region config", p.inferenceKind)
	}

	cloud, err := cloudgcp.New(ctx, cloudCfg)
	if err != nil {
		return nil, "", nil, fmt.Errorf("cloud-gcp: %w", err)
	}

	// Secrets: the KMS/Secret-Manager provider, with the workload-SA token minter (the Vertex bearer)
	// wired inside New, the data-plane Injector (the cloud-gcp Provider) wired here, and the adopter's
	// shared org API credential loaded out-of-band for the org-API lane (optional — Vertex mints instead).
	secrets, err := secretsgcp.New(ctx, secretsgcp.Config{
		ProjectID: p.project, KEKResourceName: p.kekResource, SecretPrefix: envOr("C7_SECRET_PREFIX", "console7"),
		Region: p.region, WorkloadSAEmail: p.workloadSA,
	})
	if err != nil {
		return nil, "", nil, fmt.Errorf("secrets-gcp: %w", err)
	}
	secrets.SetInjector(cloud)
	if orgKey := os.Getenv("C7_ORG_API_KEY"); orgKey != "" {
		if err := secrets.SetOrgCredential(ctx, []byte(orgKey)); err != nil {
			return nil, "", nil, fmt.Errorf("set org credential: %w", err)
		}
	}

	scm, err := scmgithub.New(scmgithub.Config{
		AppID: p.ghAppID, PrivateKeyPEM: p.ghKey, InstallationID: p.ghInstall, BaseURL: os.Getenv("C7_GH_BASE_URL"),
	})
	if err != nil {
		return nil, "", nil, fmt.Errorf("scm-github: %w", err)
	}

	// The lineage trust root: the KMS-backed CA (private key never leaves KMS). The NHI binder and the
	// evidence sink signer both certify under it; the sink + orchestrator pin its EC-P256 public anchor.
	kmsCA, err := keybrokergcp.New(ctx, keybrokergcp.Config{KeyVersionName: p.kmsKeyVersion})
	if err != nil {
		return nil, "", nil, fmt.Errorf("keybroker-gcp CA: %w", err)
	}
	sinkSigner, err := signing.NewSinkSigner(kmsCA, "c7-evidence-sink")
	if err != nil {
		return nil, "", nil, fmt.Errorf("sink signer: %w", err)
	}

	// RESIDUAL (Phase-1): no OIDC IdP provider yet — authn is a dev assertion under a process-local key,
	// so this run does NOT prove external SSO->NHI binding (banner-flagged). The rest of the lineage
	// (NHI -> signed commit, KMS-rooted) IS real.
	idpPub, idpPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, "", nil, fmt.Errorf("idp keygen: %w", err)
	}
	b := broker.New(devkit.NewDevIdentity(idpPub, nil), secrets, scm, inference, signing.NewNHIBinder(kmsCA))

	store, err := evidencegcs.New(ctx, evidencegcs.Config{Bucket: p.evidenceBucket, ObjectPrefix: envOr("C7_EVIDENCE_PREFIX", "records")})
	if err != nil {
		return nil, "", nil, fmt.Errorf("evidence-gcs: %w", err)
	}
	sink := evidence.New(store, sinkSigner, kmsCA.Root(), 0)

	// RESIDUAL (Phase-1): the fixed dev PolicySoR (no central GRC adapter yet) resolves the single
	// target repo's tier x stratum. The egress allowlist is seeded with the resolved inference endpoint.
	orch := orchestrator.New(b, cloud, sink, devkit.NewFixedPolicySoR(repo), allowlist, 30*time.Minute)
	authn := devkit.IssueDevAssertion(idpPriv, interfaces.Subject(user), time.Now().Add(time.Hour))
	return orch, authn, sink, nil
}
