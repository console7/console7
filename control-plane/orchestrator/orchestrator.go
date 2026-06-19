// Package orchestrator is the control-plane session lifecycle: it composes the provider
// seams (via the key broker, the cloud/evidence sinks, and the policy system-of-record)
// into one governed task and stamps the unbroken lineage (human Subject → per-session NHI
// → every action) at the orchestrator, because the engine's sub-agent lineage is leaky and
// cannot be the sole source of attribution (DESIGN.md §2.3, §10.5; ARCHITECTURE.md §2).
//
// It holds no keys: every credential and signature comes from the key broker as an opaque
// reference or a session signer. This package depends only on sdk/interfaces and the key
// broker — never on a concrete provider — so the same spine runs against the in-memory
// devkit fakes (Phase 1 bench) or real providers (later phases) unchanged.
package orchestrator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/console7/console7/keybroker/broker"
	"github.com/console7/console7/keybroker/signing"
	"github.com/console7/console7/sdk/interfaces"
)

// Orchestrator drives the session lifecycle over the seams. The broker mints identity and
// resolves inference/subscription; Cloud is the sandbox/egress perimeter; Evidence is the
// WORM sink; SoR is the authoritative tier × stratum lookup. All four are interface-typed
// (or the broker, which is itself seam-typed), so no concrete provider leaks into the
// control plane.
type Orchestrator struct {
	Broker   *broker.Broker
	Cloud    interfaces.CloudProvider
	Evidence interfaces.EvidenceSink
	SoR      interfaces.PolicySoR

	// EgressAllowlist seeds the session profile's default-deny perimeter — the approved
	// destinations for the lane, at minimum the inference endpoints. The boundary is
	// authoritative: a resolved inference endpoint not on this list aborts the session.
	EgressAllowlist []string
	// MaxTTL is the hard session/sandbox lifetime stamped into the profile and the
	// sandbox spec; the session and every minted credential die with it.
	MaxTTL time.Duration
}

// New returns an Orchestrator wired to the given seams and lane configuration.
func New(b *broker.Broker, cloud interfaces.CloudProvider, evidence interfaces.EvidenceSink, sor interfaces.PolicySoR, egressAllowlist []string, maxTTL time.Duration) *Orchestrator {
	return &Orchestrator{
		Broker:          b,
		Cloud:           cloud,
		Evidence:        evidence,
		SoR:             sor,
		EgressAllowlist: append([]string(nil), egressAllowlist...),
		MaxTTL:          maxTTL,
	}
}

// LaunchRequest is one session asking to run a governed task end to end.
type LaunchRequest struct {
	// Authn is the inbound, untrusted SSO assertion; the broker verifies it.
	Authn     interfaces.AuthnToken
	SessionID interfaces.SessionID
	Persona   interfaces.Persona
	Repo      interfaces.RepoRef
	Branch    string
	// Attended marks a human present for this single-user session — the discriminator for
	// subscription-backed inference (tenet 7). Headless/orchestrated launches set it false
	// and route to the org API.
	Attended bool
	// UseSubscription requests that this attended session run on the user's vaulted
	// subscription token (captured out of band at `claude /login` and sealed under the
	// user's key — DESIGN.md §2.2). The token NEVER passes through the control plane: the
	// orchestrator only asks the broker to inject the already-vaulted token into the
	// owner's sandbox by reference. Ignored when the session is unattended.
	UseSubscription bool
}

// Summary is the result of a completed session: the verified subject and NHI, the (now
// destroyed) sandbox handle, the resolved inference endpoint, the opened PR, the signed
// commit (with the digest it attests), and the number of evidence records written.
type Summary struct {
	Subject      interfaces.Subject
	NHI          string
	Sandbox      interfaces.SandboxHandle
	Inference    interfaces.BackendEndpoint
	PR           interfaces.PRRef
	CommitDigest []byte
	CommitSig    signing.Signature
	Records      int
}

// Run executes one governed task end to end, stamping a signed evidence record at every
// lifecycle step. Any failure after the sandbox is provisioned tears it down and records a
// session-aborted event before returning — the session never leaves a sandbox live.
func (o *Orchestrator) Run(ctx context.Context, req LaunchRequest) (Summary, error) {
	if o.Broker == nil || o.Cloud == nil || o.Evidence == nil || o.SoR == nil {
		return Summary{}, errors.New("orchestrator: missing a required seam (broker/cloud/evidence/sor)")
	}
	// Validate the broker's own seams up front, BEFORE provisioning anything, so a
	// misconfigured broker fails closed without leaking a sandbox (a later nil-seam call
	// would otherwise abort mid-session — or, without the broker's own guards, panic).
	if o.Broker.Inference == nil || o.Broker.SCM == nil || o.Broker.Secrets == nil {
		return Summary{}, errors.New("orchestrator: broker is missing a required seam (inference/scm/secrets)")
	}

	// 1. Authenticate the human BEFORE touching the policy system-of-record, so an
	// unauthenticated caller cannot probe which targets exist or spend SoR capacity. The
	// broker verifies the SSO assertion; a caller-asserted subject is never trusted.
	subject, err := o.Broker.Authenticate(ctx, req.Authn)
	if err != nil {
		return Summary{}, err
	}

	// 2. Resolve the target's profile through the PolicySoR seam (fail closed on unknown),
	// now that the caller is authenticated.
	profile, err := ResolveProfile(ctx, o.SoR, req.Repo, req.Persona, o.EgressAllowlist, o.MaxTTL)
	if err != nil {
		return Summary{}, err
	}

	// 3. Mint the per-session identity: bind the NHI (its signing key stays in the broker)
	// and mint the ephemeral cloud + SCM credentials. The deadline is the hard session
	// lifetime — every credential is capped to it by its seam. The broker re-verifies the
	// assertion (defence in depth; MintSessionIdentity never trusts a caller subject).
	deadline := time.Now().Add(profile.MaxTTL)
	minted, err := o.Broker.MintSessionIdentity(ctx, broker.SessionRequest{
		Authn:           req.Authn,
		SessionID:       req.SessionID,
		Persona:         req.Persona,
		Repo:            req.Repo,
		Branch:          req.Branch,
		Scopes:          []string{"repo:" + req.Repo.Owner + "/" + req.Repo.Name},
		TTL:             profile.MaxTTL,
		SessionDeadline: deadline,
	})
	if err != nil {
		return Summary{}, err
	}
	// The minted identity's verified subject is authoritative.
	subject = minted.Identity.Subject
	nhi := minted.NHI
	// The session's signing key lives in the broker; release it at teardown so it cannot
	// outlive the session. cleanupCtx is detached from the request context so teardown still
	// runs even if the caller cancels or times out mid-session.
	cleanupCtx := context.WithoutCancel(ctx)
	defer o.Broker.ReleaseSession(req.SessionID)

	// emit writes a signed evidence record under the given context; stamp wraps it for the
	// happy path (request context, counted). A failure to record evidence is itself fatal —
	// an unattested action must not proceed silently. session-aborted records are emitted on
	// the cleanup context (so a cancelled request cannot erase them) and are uncounted.
	records := 0
	emit := func(c context.Context, event, detail string) error {
		return o.appendSigned(c, req.SessionID, subject, req.Persona, nhi, event, detail)
	}
	stamp := func(event, detail string) error {
		if err := emit(ctx, event, detail); err != nil {
			return err
		}
		records++
		return nil
	}
	if err := stamp("session-start", string(subject)+" -> "+nhi); err != nil {
		return Summary{}, err
	}

	// 4. Provision the sandbox with the profile's default-deny egress.
	sandbox, err := o.Cloud.ProvisionSandbox(ctx, interfaces.SandboxSpec{
		SessionID: req.SessionID,
		Subject:   subject,
		Persona:   req.Persona,
		Egress:    interfaces.EgressPolicy{Allowlist: profile.EgressAllowlist},
		MaxTTL:    profile.MaxTTL,
	})
	if err != nil {
		// No sandbox to tear down; record the failure against the chain and surface it.
		_ = emit(cleanupCtx, "session-aborted", "provision-sandbox: "+err.Error())
		return Summary{}, fmt.Errorf("orchestrator: provision-sandbox: %w", err)
	}

	// From here on, any failure must tear the sandbox down — never leave it live. Teardown
	// uses cleanupCtx (not the request ctx), so a cancelled/expired request cannot skip it,
	// and a teardown failure is surfaced (joined with the cause), never swallowed: a failed
	// destroy can mean the sandbox and injected credentials are still live.
	abort := func(cause error, stage string) (Summary, error) {
		outErr := fmt.Errorf("orchestrator: %s: %w", stage, cause)
		if derr := o.Cloud.DestroySandbox(cleanupCtx, sandbox); derr != nil {
			outErr = errors.Join(outErr, fmt.Errorf("orchestrator: destroy-sandbox after %s failed (sandbox may be live): %w", stage, derr))
		}
		_ = emit(cleanupCtx, "session-aborted", stage+": "+cause.Error())
		return Summary{}, outErr
	}
	if err := stamp("sandbox-provisioned", sandbox.ID); err != nil {
		return abort(err, "sandbox-provisioned-evidence")
	}

	// 5. Resolve inference. Subscription backs a session ONLY when it is attended AND the
	// user opted into their vaulted subscription; an attended session without it routes the
	// org API like any unattended session (tenet 7 — subscription is permitted, never
	// mandatory). The resolved endpoint MUST already be on the egress allowlist — the
	// boundary is authoritative, so an endpoint the perimeter would deny aborts the session
	// rather than running against an unreachable model.
	useSubscription := req.Attended && req.UseSubscription
	mode := interfaces.ModeOrgAPI
	if useSubscription {
		mode = interfaces.ModeSubscription
	}
	endpoint, err := o.Broker.ResolveInference(ctx, interfaces.InferenceSelection{
		SessionID:     req.SessionID,
		Subject:       subject,
		Mode:          mode,
		Attended:      req.Attended,
		Beneficiaries: 1,
	})
	if err != nil {
		return abort(err, "resolve-inference")
	}
	if !onAllowlist(endpoint.URL, profile.EgressAllowlist) {
		return abort(fmt.Errorf("resolved endpoint %q is not on the egress allowlist", endpoint.URL), "egress-check")
	}
	if err := stamp("inference-resolved", endpoint.URL); err != nil {
		return abort(err, "inference-evidence")
	}

	// 4b. Narrow the sandbox's egress to exactly the resolved endpoint — the perimeter is
	// per-session, not the whole lane union (so an org-API session is not also granted reach
	// to the subscription endpoint). Approved registry/MCP destinations fold into this
	// allowlist in later phases; for the single-lane PoC the inference endpoint is the only
	// permitted destination. ApplyEgressPolicy enforces narrow-only at the boundary.
	if err := o.Cloud.ApplyEgressPolicy(ctx, sandbox, interfaces.EgressPolicy{Allowlist: []string{endpoint.URL}}); err != nil {
		return abort(err, "narrow-egress")
	}
	if err := stamp("egress-narrowed", endpoint.URL); err != nil {
		return abort(err, "egress-evidence")
	}

	// 6. (subscription) Inject the user's ALREADY-VAULTED subscription token into their OWN
	// sandbox by reference — the plaintext was sealed under their key at login and never
	// passes through the control plane. The seam enforces attended && single-beneficiary &&
	// owning-sandbox.
	if useSubscription {
		if err := o.Broker.InjectSubscription(ctx, interfaces.SubscriptionInjection{
			Subject:       subject,
			SessionID:     req.SessionID,
			Sandbox:       sandbox,
			Attended:      true,
			Beneficiaries: 1,
		}); err != nil {
			return abort(err, "inject-subscription")
		}
		if err := stamp("subscription-injected", sandbox.ID); err != nil {
			return abort(err, "subscription-evidence")
		}
	}

	// 7. "Do the work" → a commit digest → sign it with the session NHI (via the broker, so
	// the key never enters the control plane). The signature is the crypto-attested output,
	// recorded in the chain (tenet 6; ROADMAP Phase 1).
	digest := commitDigest(req)
	commitSig, err := o.Broker.SignSession(ctx, req.SessionID, digest)
	if err != nil {
		return abort(err, "sign-commit")
	}
	if err := stamp("commit-signed", hex.EncodeToString(digest)); err != nil {
		return abort(err, "commit-evidence")
	}

	// 8. PR-only exit: propose the change as a PR. The session never merges or actuates —
	// author, approve, and actuate are separated (tenet 5/6).
	prRef, err := o.Broker.OpenPullRequest(ctx, interfaces.PullRequest{
		Repo:  req.Repo,
		Head:  req.Branch,
		Base:  "main",
		Title: "Console7 session " + string(req.SessionID),
		Body:  "Proposed by attended author session; lineage " + string(subject) + " -> " + nhi + ".",
	})
	if err != nil {
		return abort(err, "open-pr")
	}
	if err := stamp("pr-opened", prRef.URL); err != nil {
		return abort(err, "pr-evidence")
	}

	// 9. Teardown. Destruction is irreversible and wipes the injected token; it uses
	// cleanupCtx so a cancelled request cannot skip it. Record the end.
	if err := o.Cloud.DestroySandbox(cleanupCtx, sandbox); err != nil {
		// Use the cleanup context (not the possibly-cancelled request ctx) so a sink that
		// honours cancellation still records this teardown failure — the sandbox may be live.
		_ = emit(cleanupCtx, "session-aborted", "destroy-sandbox: "+err.Error())
		return Summary{}, fmt.Errorf("orchestrator: destroy-sandbox: %w", err)
	}
	if err := stamp("session-end", string(req.SessionID)); err != nil {
		return Summary{}, err
	}

	return Summary{
		Subject:      subject,
		NHI:          nhi,
		Sandbox:      sandbox,
		Inference:    endpoint,
		PR:           prRef,
		CommitDigest: digest,
		CommitSig:    commitSig,
		Records:      records,
	}, nil
}

// commitDigest derives the digest the session "produces" and signs. The real engine emits
// a real commit; the spine signs a deterministic digest over the work's coordinates so the
// attestation is exercised end to end without wrapping the engine yet (tenet 8 — that wrap
// lands with sandbox/base-image in a later Phase-1 PR).
func commitDigest(req LaunchRequest) []byte {
	h := sha256.New()
	// Domain-tag the commit-signing input so a commit signature can never be confused with
	// an evidence-record signature minted by the same NHI key (cf. evidenceDomain).
	h.Write([]byte("c7-commit-v1"))
	for _, s := range []string{req.Repo.Host, req.Repo.Owner, req.Repo.Name, req.Branch, string(req.SessionID)} {
		var u8 [8]byte
		binary.BigEndian.PutUint64(u8[:], uint64(len(s)))
		h.Write(u8[:])
		h.Write([]byte(s))
	}
	return h.Sum(nil)
}

// onAllowlist reports whether url is an exact member of the default-deny allowlist. The
// bench compares full endpoint URLs; a real perimeter resolves and matches by host/port.
func onAllowlist(url string, allowlist []string) bool {
	for _, a := range allowlist {
		if a == url {
			return true
		}
	}
	return false
}

// evidenceDomain separates the bytes signed for an evidence record from every other use of
// the session NHI key (cf. the commit-signing domain in commitDigest and certTBS in the
// signing package). A signature minted for one context can never be presented as another.
const evidenceDomain = "c7-evidence-v1"

// stampedPayload is the body of every evidence record the orchestrator emits: the event and
// its detail, plus the session NHI's signature over the record's full lineage tuple. Storing
// the signature inside the WORM payload means each record carries its own lineage proof,
// independent of the hash chain that links records together.
type stampedPayload struct {
	Event  string            `json:"event"`
	Detail string            `json:"detail"`
	Sig    signing.Signature `json:"sig"`
}

// appendSigned signs the record's full lineage tuple (Subject, SessionID, Persona, NHI,
// event, detail) via the broker (the key never enters the control plane), wraps the
// signature in the record payload, and appends the record. The Subject/SessionID/Persona
// stamped as record fields are the SAME values bound into the signature, so a tampered
// attribution column breaks verification.
func (o *Orchestrator) appendSigned(ctx context.Context, session interfaces.SessionID, subject interfaces.Subject, persona interfaces.Persona, nhi, event, detail string) error {
	sig, err := o.Broker.SignSession(ctx, session, payloadTBS(subject, session, persona, nhi, event, detail))
	if err != nil {
		return err
	}
	payload, err := json.Marshal(stampedPayload{Event: event, Detail: detail, Sig: sig})
	if err != nil {
		return err
	}
	ref, err := o.Evidence.Append(ctx, interfaces.EvidenceRecord{
		SessionID:  session,
		Subject:    subject,
		Persona:    persona,
		Type:       event,
		ObservedAt: time.Now().UTC(),
		Payload:    payload,
	})
	if err != nil {
		return err
	}
	// Mirror the committed record to the adopter's SIEM via the Stream hook. It supplements
	// (never replaces) the durable WORM append, but a session's evidence is load-bearing, so
	// a failed mirror fails the stamp closed rather than silently dropping the forward.
	return o.Evidence.Stream(ctx, ref)
}

// payloadTBS is the canonical, domain-tagged, length-prefixed bytes the per-record lineage
// signature covers. Binding Subject/SessionID/Persona into the signed bytes is what makes
// the proof attributable: it ties the signature to the exact lineage columns an auditor
// reads off the record, not merely to "the NHI signed some event".
func payloadTBS(subject interfaces.Subject, session interfaces.SessionID, persona interfaces.Persona, nhi, event, detail string) []byte {
	var b bytes.Buffer
	for _, s := range []string{evidenceDomain, string(subject), string(session), string(persona), nhi, event, detail} {
		var u8 [8]byte
		binary.BigEndian.PutUint64(u8[:], uint64(len(s)))
		b.Write(u8[:])
		b.WriteString(s)
	}
	return b.Bytes()
}

// VerifyRecordPayload checks the per-record lineage signature an orchestrator stamped into an
// evidence record's payload. Under the trusted CA root, the embedded signature must verify
// over the lineage tuple RECOMPUTED FROM THE RECORD'S OWN columns (Subject, SessionID,
// Persona, event), and the certificate-bound Subject/SessionID inside the signature must
// equal those columns. So a record whose attribution column was altered — or onto which a
// genuine signature from another record/session was replayed — fails. It lets an auditor
// prove every recorded event traces to the stamped human → NHI, not merely that the chain is
// unbroken.
func VerifyRecordPayload(caRoot ed25519.PublicKey, rec interfaces.EvidenceRecord) error {
	var sp stampedPayload
	if err := json.Unmarshal(rec.Payload, &sp); err != nil {
		return fmt.Errorf("orchestrator: undecodable evidence payload: %w", err)
	}
	if sp.Event != rec.Type {
		return errors.New("orchestrator: evidence payload event does not match record type")
	}
	// The signature must cover THIS record's stamped lineage; recomputing the TBS from the
	// record's own columns binds the proof to the attribution an auditor reads.
	tbs := payloadTBS(rec.Subject, rec.SessionID, rec.Persona, sp.Sig.NHI, sp.Event, sp.Detail)
	if err := signing.Verify(caRoot, tbs, sp.Sig); err != nil {
		return err
	}
	// Defence in depth: signing.Verify binds the signature's Subject/SessionID to the CA
	// certificate, so requiring they equal the record's columns rejects a same-key replay
	// onto a record with a different stamped subject/session.
	if sp.Sig.Subject != rec.Subject || sp.Sig.SessionID != rec.SessionID {
		return errors.New("orchestrator: record lineage columns do not match the certified signature")
	}
	return nil
}
