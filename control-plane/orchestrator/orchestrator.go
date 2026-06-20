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
	"strings"
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

// session carries the per-run state threaded across the lifecycle phases so each phase
// is a small method rather than one 80-statement function. The session-bounding defer
// (ReleaseSession) and the evidence/seal ORDERING stay in Run; these helpers only
// relocate code, never reorder effects.
type session struct {
	o          *Orchestrator
	ctx        context.Context
	cleanupCtx context.Context
	req        LaunchRequest
	subject    interfaces.Subject
	nhi        string
	profile    interfaces.SessionProfile
	deadline   time.Time
	sandbox    interfaces.SandboxHandle
	records    int
	// work outputs, filled by the operate phases and read into the final Summary.
	endpoint  interfaces.BackendEndpoint
	digest    []byte
	commitSig signing.Signature
	prRef     interfaces.PRRef
}

// emit writes a signed evidence record under the given context. A failure to record
// evidence is itself fatal — an unattested action must not proceed silently.
func (s *session) emit(c context.Context, event, detail string) error {
	return s.o.appendSigned(c, s.req.SessionID, s.subject, s.req.Persona, s.nhi, event, detail)
}

// stamp wraps emit for the happy path: it records under the request context and counts the
// record toward the Summary's tally.
func (s *session) stamp(event, detail string) error {
	if err := s.emit(s.ctx, event, detail); err != nil {
		return err
	}
	s.records++
	return nil
}

// abort tears the sandbox down — never leave it live — and records a session-aborted event
// before returning. Teardown uses cleanupCtx (not the request ctx), so a cancelled/expired
// request cannot skip it, and a teardown failure is surfaced (joined with the cause), never
// swallowed: a failed destroy can mean the sandbox and injected credentials are still live.
func (s *session) abort(cause error, stage string) error {
	outErr := fmt.Errorf("orchestrator: %s: %w", stage, cause)
	if derr := s.o.Cloud.DestroySandbox(s.cleanupCtx, s.sandbox); derr != nil {
		outErr = errors.Join(outErr, fmt.Errorf("orchestrator: destroy-sandbox after %s failed (sandbox may be live): %w", stage, derr))
	}
	// Surface (never swallow) a failure to record the abort — e.g. SignSession refusing to
	// sign past the session deadline on a session that overran. A dropped close-out record
	// must be visible so an operator can escalate. (Residual, now PARTIALLY closed: the
	// sink's own checkpoint seal below uses a long-lived signer that outlives the work
	// deadline, so even when the per-record close-out lineage stamp fails the chain still
	// gets a fresh sink-signed head. The per-record close-out lineage signature still needs a
	// teardown-scoped session signer; tracked for the keybroker.)
	if eerr := s.emit(s.cleanupCtx, "session-aborted", stage+": "+cause.Error()); eerr != nil {
		outErr = errors.Join(outErr, fmt.Errorf("orchestrator: failed to record session-aborted: %w", eerr))
	}
	// Seal a sink-signed checkpoint over the chain head at teardown (no-op if the sink does
	// not support it). This anchors the close-out even if the per-record stamp above failed.
	return s.o.sealOrJoin(s.cleanupCtx, outErr, "on abort")
}

// prepare runs the linear pre-provision setup: it validates the seams, authenticates the
// human, resolves the target profile, and mints the per-session identity. It returns the
// session state Run then threads through the lifecycle phases. Nothing here provisions an
// external resource, so a failure simply returns the error — there is no sandbox to tear
// down yet and no evidence has been committed.
func (o *Orchestrator) prepare(ctx context.Context, req LaunchRequest) (*session, error) {
	if o.Broker == nil || o.Cloud == nil || o.Evidence == nil || o.SoR == nil {
		return nil, errors.New("orchestrator: missing a required seam (broker/cloud/evidence/sor)")
	}
	// Validate the broker's own seams up front, BEFORE provisioning anything, so a
	// misconfigured broker fails closed without leaking a sandbox (a later nil-seam call
	// would otherwise abort mid-session — or, without the broker's own guards, panic).
	if o.Broker.Inference == nil || o.Broker.SCM == nil || o.Broker.Secrets == nil {
		return nil, errors.New("orchestrator: broker is missing a required seam (inference/scm/secrets)")
	}

	// 1. Authenticate the human BEFORE touching the policy system-of-record, so an
	// unauthenticated caller cannot probe which targets exist or spend SoR capacity. The
	// broker verifies the SSO assertion; a caller-asserted subject is never trusted.
	if _, err := o.Broker.Authenticate(ctx, req.Authn); err != nil {
		return nil, err
	}

	// 2. Resolve the target's profile through the PolicySoR seam (fail closed on unknown),
	// now that the caller is authenticated.
	profile, err := ResolveProfile(ctx, o.SoR, req.Repo, req.Persona, o.EgressAllowlist, o.MaxTTL)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	// The minted identity's verified subject is authoritative.
	// cleanupCtx is detached from the request context so teardown still runs even if the
	// caller cancels or times out mid-session.
	//
	// CAUTION: the identity is now minted but its broker-held signing key is not yet released.
	// The caller (Run) MUST `defer o.Broker.ReleaseSession(req.SessionID)` immediately on
	// success, before any further fallible step — a fallible call inserted between this return
	// and that defer would leak the session's signing key past its lifetime.
	return &session{
		o: o, ctx: ctx, cleanupCtx: context.WithoutCancel(ctx), req: req,
		subject: minted.Identity.Subject, nhi: minted.NHI, profile: profile, deadline: deadline,
	}, nil
}

// resolveInference resolves the session's model endpoint, gates it against the egress
// allowlist, narrows the sandbox perimeter to exactly that endpoint, and — for a
// subscription session — injects the owner's vaulted token. Every failure path aborts.
func (o *Orchestrator) resolveInference(s *session) error {
	// 5. Resolve inference. Subscription backs a session ONLY when it is attended AND the
	// user opted into their vaulted subscription; an attended session without it routes the
	// org API like any unattended session (tenet 7 — subscription is permitted, never
	// mandatory). The resolved endpoint MUST already be on the egress allowlist — the
	// boundary is authoritative, so an endpoint the perimeter would deny aborts the session
	// rather than running against an unreachable model.
	useSubscription := s.req.Attended && s.req.UseSubscription
	mode := interfaces.ModeOrgAPI
	if useSubscription {
		mode = interfaces.ModeSubscription
	}
	endpoint, err := o.Broker.ResolveInference(s.ctx, interfaces.InferenceSelection{
		SessionID:     s.req.SessionID,
		Subject:       s.subject,
		Mode:          mode,
		Attended:      s.req.Attended,
		Beneficiaries: 1,
	})
	if err != nil {
		return s.abort(err, "resolve-inference")
	}
	if !onAllowlist(endpoint.URL, s.profile.EgressAllowlist) {
		return s.abort(fmt.Errorf("resolved endpoint %q is not on the egress allowlist", endpoint.URL), "egress-check")
	}
	s.endpoint = endpoint
	if err := s.stamp("inference-resolved", endpoint.URL); err != nil {
		return s.abort(err, "inference-evidence")
	}

	// 4b. Narrow the sandbox's egress to exactly the resolved endpoint — the perimeter is
	// per-session, not the whole lane union (so an org-API session is not also granted reach
	// to the subscription endpoint). Approved registry/MCP destinations fold into this
	// allowlist in later phases; for the single-lane PoC the inference endpoint is the only
	// permitted destination. ApplyEgressPolicy enforces narrow-only at the boundary.
	if err := o.Cloud.ApplyEgressPolicy(s.ctx, s.sandbox, interfaces.EgressPolicy{Allowlist: []string{endpoint.URL}}); err != nil {
		return s.abort(err, "narrow-egress")
	}
	if err := s.stamp("egress-narrowed", endpoint.URL); err != nil {
		return s.abort(err, "egress-evidence")
	}

	// 6. (subscription) Inject the user's ALREADY-VAULTED subscription token into their OWN
	// sandbox by reference — the plaintext was sealed under their key at login and never
	// passes through the control plane. The seam enforces attended && single-beneficiary &&
	// owning-sandbox.
	if useSubscription {
		if err := o.Broker.InjectSubscription(s.ctx, interfaces.SubscriptionInjection{
			Subject:       s.subject,
			SessionID:     s.req.SessionID,
			Sandbox:       s.sandbox,
			Attended:      true,
			Beneficiaries: 1,
		}); err != nil {
			return s.abort(err, "inject-subscription")
		}
		if err := s.stamp("subscription-injected", s.sandbox.ID); err != nil {
			return s.abort(err, "subscription-evidence")
		}
	}
	return nil
}

// propose does the work, signs the resulting commit digest with the session NHI, and opens
// the change as a PR (the only outward side-effect). Every failure path aborts.
func (o *Orchestrator) propose(s *session) error {
	// 7. "Do the work" → a commit digest → sign it with the session NHI (via the broker, so
	// the key never enters the control plane). The signature is the crypto-attested output,
	// recorded in the chain (tenet 6; ROADMAP Phase 1).
	s.digest = commitDigest(s.req)
	commitSig, err := o.Broker.SignSession(s.ctx, s.req.SessionID, s.digest)
	if err != nil {
		return s.abort(err, "sign-commit")
	}
	s.commitSig = commitSig
	if err := s.stamp("commit-signed", hex.EncodeToString(s.digest)); err != nil {
		return s.abort(err, "commit-evidence")
	}

	// 8. PR-only exit: propose the change as a PR. The session never merges or actuates —
	// author, approve, and actuate are separated (tenet 5/6).
	//
	// Write-ahead the INTENT before the external side-effect: the PR is the one irreversible
	// outward action, so the WORM log must durably record that we are opening it BEFORE the
	// call, not only confirm it after. Otherwise a post-open evidence failure would leave a PR
	// open with no record of it. (Residual for a real SCM provider: if the post-open
	// confirmation cannot commit, a compensating close / idempotent reconcile is also needed;
	// tracked for providers/scm-github.)
	if err := s.stamp("pr-opening", s.req.Branch+" -> main"); err != nil {
		return s.abort(err, "pr-intent-evidence")
	}
	prRef, err := o.Broker.OpenPullRequest(s.ctx, interfaces.PullRequest{
		Repo:  s.req.Repo,
		Head:  s.req.Branch,
		Base:  "main",
		Title: "Console7 session " + string(s.req.SessionID),
		Body:  "Proposed by attended author session; lineage " + string(s.subject) + " -> " + s.nhi + ".",
	})
	if err != nil {
		return s.abort(err, "open-pr")
	}
	s.prRef = prRef
	if err := s.stamp("pr-opened", prRef.URL); err != nil {
		return s.abort(err, "pr-evidence")
	}
	return nil
}

// Run executes one governed task end to end, stamping a signed evidence record at every
// lifecycle step. Any failure after the sandbox is provisioned tears it down and records a
// session-aborted event before returning — the session never leaves a sandbox live.
func (o *Orchestrator) Run(ctx context.Context, req LaunchRequest) (Summary, error) {
	s, err := o.prepare(ctx, req)
	if err != nil {
		return Summary{}, err
	}
	// The session's signing key lives in the broker; release it at teardown so it cannot
	// outlive the session (registered after the identity is minted).
	defer o.Broker.ReleaseSession(req.SessionID)

	if err := s.stamp("session-start", string(s.subject)+" -> "+s.nhi); err != nil {
		// stamp may have committed the record but failed on Stream; route through sealOrJoin so
		// even this pre-provision terminal path anchors any committed head (a no-op if nothing was
		// committed, since the sink cannot seal an empty chain).
		return Summary{}, o.sealOrJoin(s.cleanupCtx, err, "at session-start")
	}

	// 4. Provision the sandbox with the profile's default-deny egress.
	sandbox, err := o.Cloud.ProvisionSandbox(ctx, interfaces.SandboxSpec{
		SessionID: req.SessionID,
		Subject:   s.subject,
		Persona:   req.Persona,
		Egress:    interfaces.EgressPolicy{Allowlist: s.profile.EgressAllowlist},
		// Cap the sandbox to the time REMAINING until the session deadline, not a fresh full
		// MaxTTL: identity/SCM minting and early evidence already consumed part of the budget,
		// so the sandbox (and any injected material) must die with the same absolute deadline
		// the credentials were capped to, even if teardown is missed.
		MaxTTL: time.Until(s.deadline),
	})
	if err != nil {
		// No sandbox to tear down; record the failure against the chain and surface it. The
		// session-start record is already committed, so seal a checkpoint here too (joined into
		// the error) — this is a terminal path with committed evidence.
		_ = s.emit(s.cleanupCtx, "session-aborted", "provision-sandbox: "+err.Error())
		return Summary{}, o.sealOrJoin(s.cleanupCtx, fmt.Errorf("orchestrator: provision-sandbox: %w", err), "on provision failure")
	}
	s.sandbox = sandbox
	if err := s.stamp("sandbox-provisioned", sandbox.ID); err != nil {
		return Summary{}, s.abort(err, "sandbox-provisioned-evidence")
	}

	if err := o.resolveInference(s); err != nil {
		return Summary{}, err
	}
	if err := o.propose(s); err != nil {
		return Summary{}, err
	}

	// 9. Teardown. Destruction is irreversible and wipes the injected token; it uses
	// cleanupCtx so a cancelled request cannot skip it. Record the end.
	if err := o.Cloud.DestroySandbox(s.cleanupCtx, s.sandbox); err != nil {
		// Use the cleanup context (not the possibly-cancelled request ctx) so a sink that
		// honours cancellation still records this teardown failure — the sandbox may be live.
		_ = s.emit(s.cleanupCtx, "session-aborted", "destroy-sandbox: "+err.Error())
		return Summary{}, o.sealOrJoin(s.cleanupCtx, fmt.Errorf("orchestrator: destroy-sandbox: %w", err), "on destroy failure")
	}
	// The terminal session-end record has the same cancellation-resilience requirement as the
	// abort record: teardown already succeeded on cleanupCtx, so a cancelled request must not
	// drop the close-out evidence. Emit it on cleanupCtx (and count it). Even if this per-record
	// close-out fails (e.g. the session signer passed its deadline), seal the chain anyway — the
	// long-lived sink signer can still anchor the head — and surface both errors.
	if err := s.emit(s.cleanupCtx, "session-end", string(req.SessionID)); err != nil {
		return Summary{}, o.sealOrJoin(s.cleanupCtx, err, "at session-end")
	}
	s.records++

	// Seal a sink-signed checkpoint over the final chain head so every completed session ends
	// with a fresh, sink-attested close-out (no-op if the sink does not support sealing).
	if err := o.sealOrJoin(s.cleanupCtx, nil, "at session-end"); err != nil {
		return Summary{}, err
	}

	return Summary{
		Subject:      s.subject,
		NHI:          s.nhi,
		Sandbox:      s.sandbox,
		Inference:    s.endpoint,
		PR:           s.prRef,
		CommitDigest: s.digest,
		CommitSig:    s.commitSig,
		Records:      s.records,
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

// evidenceSealer is the optional capability an EvidenceSink may implement to seal a
// sink-signed checkpoint over its chain head (control-plane/evidence implements it; the
// devkit MemEvidence double does not). The orchestrator seals at terminal events so the
// evidence chain always carries a fresh, sink-signed head at close-out. Crucially the sink's
// checkpoint signer is long-lived — NOT session-deadline-bound like the per-record lineage
// signer (broker.SignSession) — so a session that overran its work deadline can still seal
// its close-out, partially closing the teardown residual noted in abort(). It is reached by
// type assertion (not added to the EvidenceSink seam) so the spine still runs unchanged
// against a sink that does not implement it.
type evidenceSealer interface {
	Seal(ctx context.Context) error
}

// sealCheckpoint seals a sink-signed checkpoint if the evidence sink supports it; a sink that
// does not (the bench double) is a no-op. Errors are returned for the caller to surface.
func (o *Orchestrator) sealCheckpoint(ctx context.Context) error {
	if sealer, ok := o.Evidence.(evidenceSealer); ok {
		return sealer.Seal(ctx)
	}
	return nil
}

// sealOrJoin seals a terminal checkpoint and folds any seal failure into cause (which may be
// nil on the success path). EVERY terminal return that may have committed evidence routes
// through this, so a teardown always anchors the chain with a sink-signed head and a seal
// failure is always surfaced — no terminal path can silently skip the seal. `where` names the
// path for the joined error.
func (o *Orchestrator) sealOrJoin(ctx context.Context, cause error, where string) error {
	if serr := o.sealCheckpoint(ctx); serr != nil {
		return errors.Join(cause, fmt.Errorf("orchestrator: failed to seal evidence checkpoint %s: %w", where, serr))
	}
	return cause
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
	// Bind the persona column to the persona CERTIFIED into the NHI ("nhi/<session>/<persona>").
	// SignSession is a generic signing oracle, so without this a caller holding a live author
	// NHI could sign an evidence TBS that claims PersonaOperate and have it verify; tying
	// rec.Persona to the cert's NHI rejects such cross-persona forged attribution.
	if nhiPersona(sp.Sig.NHI) != string(rec.Persona) {
		return errors.New("orchestrator: record persona does not match the certified NHI")
	}
	return nil
}

// nhiPersona extracts the persona segment a DevCA-issued NHI certifies — the NHI has the
// form "nhi/<session>/<persona>", so the persona is the final path segment.
func nhiPersona(nhi string) string {
	if i := strings.LastIndex(nhi, "/"); i >= 0 {
		return nhi[i+1:]
	}
	return ""
}
