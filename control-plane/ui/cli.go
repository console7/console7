// Package ui is the Console7 control-plane front end. Today it is the THIN c7 CLI surface (cmd/c7):
// the minimum to launch one governed session, watch its lifecycle, and review the proposed PR +
// evidence verdict over the orchestrator's existing LaunchRequest/Summary seam. It holds NO secrets
// and adds NO new control path — it is a thin client of the orchestrator (DESIGN.md §1.1). The
// browser/SSE/SSO web gateway the README describes is deferred; this is the terminal realisation.
package ui

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/console7/console7/control-plane/orchestrator"
	"github.com/console7/console7/sdk/interfaces"
)

// Runner is the orchestrator surface the CLI drives — just Run. *orchestrator.Orchestrator satisfies
// it; tests supply a fake so the CLI's request-building and rendering are exercised without wiring
// the whole seam spine.
type Runner interface {
	Run(ctx context.Context, req orchestrator.LaunchRequest) (orchestrator.Summary, error)
}

// EvidenceVerifier verifies the session's WORM evidence chain for the review verdict. The
// control-plane evidence Sink satisfies it. Optional: a nil verifier renders the record count
// without a verified/invalid verdict.
type EvidenceVerifier interface {
	// VerifyChain checks the hash-chain integrity (sink-authoritative ordering + the tamper-evidence
	// link between records).
	VerifyChain() error
	// VerifyLineage verifies EVERY record's per-record lineage signature: it calls perRecord with the
	// sink's trust root, the record's AUTHORITATIVE chain sequence, and the record. The orchestrator's
	// VerifyRecordPayload satisfies perRecord. This is what catches a forged/replayed record whose
	// (secret-less) chain hash is recomputable but whose position-bound NHI signature cannot be
	// re-minted — i.e. it makes the chain tamper-RESISTANT, not merely tamper-evident.
	VerifyLineage(perRecord func(caRoot crypto.PublicKey, seq uint64, rec interfaces.EvidenceRecord) error) error
}

// LaunchSpec is the CLI's flag-derived description of one session to launch — the thin, validated
// surface between the command line and orchestrator.LaunchRequest.
type LaunchSpec struct {
	SessionID       string
	Repo            string // "owner/name" (host defaults to github.com) or "host/owner/name"
	Branch          string
	Prompt          string
	Persona         string // "author" (default) | "operate"
	Attended        bool
	UseSubscription bool
}

// toRequest validates the spec and builds an orchestrator.LaunchRequest carrying authn. The CLI
// never holds credentials: the authn token is an SSO assertion obtained out-of-band.
func (s LaunchSpec) toRequest(authn interfaces.AuthnToken) (orchestrator.LaunchRequest, error) {
	repo, err := ParseRepo(s.Repo)
	if err != nil {
		return orchestrator.LaunchRequest{}, err
	}
	id := strings.TrimSpace(s.SessionID)
	if id == "" {
		return orchestrator.LaunchRequest{}, errors.New("c7: --session-id is required")
	}
	branch := strings.TrimSpace(s.Branch)
	if branch == "" {
		return orchestrator.LaunchRequest{}, errors.New("c7: --branch is required")
	}
	if strings.TrimSpace(s.Prompt) == "" {
		return orchestrator.LaunchRequest{}, errors.New("c7: --prompt is required")
	}
	persona, err := parsePersona(s.Persona)
	if err != nil {
		return orchestrator.LaunchRequest{}, err
	}
	return orchestrator.LaunchRequest{
		Authn:     authn,
		SessionID: interfaces.SessionID(id),
		Persona:   persona,
		Repo:      repo,
		Branch:    branch,
		Prompt:    s.Prompt,
		// SAST-DEFERRED VVAH-2026-06-25 #10: `--attended` is client-asserted (no TTY check, no OIDC
		// claim, no server challenge), so an unattended CI/cron run can self-declare attendance and
		// route onto a subscription token. Deriving attendance from a verified runtime/OIDC signal is
		// deferred to Phase 3 (real IdP); see docs/ROADMAP.md "SAST carry-forward". KNOWN/ACCEPTED.
		Attended:        s.Attended,
		UseSubscription: s.Attended && s.UseSubscription, // subscription is attended-only (GOAL.md tenet 2)
	}, nil
}

// ParseRepo accepts "owner/name" (host defaults to github.com) or "host/owner/name". Exported so the
// command wiring can resolve the repo (e.g. to register it with a PolicySoR) before launch.
func ParseRepo(s string) (interfaces.RepoRef, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i]) // normalize per-part whitespace; an all-blank part is caught below
	}
	switch len(parts) {
	case 2:
		if parts[0] == "" || parts[1] == "" {
			break
		}
		return interfaces.RepoRef{Host: "github.com", Owner: parts[0], Name: parts[1]}, nil
	case 3:
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			break
		}
		return interfaces.RepoRef{Host: parts[0], Owner: parts[1], Name: parts[2]}, nil
	}
	return interfaces.RepoRef{}, fmt.Errorf("c7: --repo %q must be owner/name or host/owner/name", s)
}

// parsePersona maps the flag to a persona; empty defaults to author.
func parsePersona(s string) (interfaces.Persona, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "author":
		return interfaces.PersonaAuthor, nil
	case "operate":
		return interfaces.PersonaOperate, nil
	default:
		return "", fmt.Errorf("c7: --persona %q must be author or operate", s)
	}
}

// errWriter wraps an io.Writer and captures the FIRST write error, so the renderer can stream many
// lines and the caller checks once (console writes rarely fail, but the error is lint-tracked).
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

// Launch runs one session end to end through the orchestrator and writes its lifecycle + the proposed
// PR + the evidence-chain verdict to w. It is the whole c7 "launch / watch / review" surface: the
// orchestrator's Run is synchronous and returns only a terminal Summary, so progress is staged log
// lines around that call rather than a streamed event bus (deliberately thin). It returns Run's error
// (already printed) so the caller can set a non-zero exit code; a write error is returned only when
// the run itself succeeded.
func Launch(ctx context.Context, runner Runner, authn interfaces.AuthnToken, spec LaunchSpec, ev EvidenceVerifier, w io.Writer) error {
	e := &errWriter{w: w}
	req, err := spec.toRequest(authn)
	if err != nil {
		// A usage/validation error is surfaced here (not silently swallowed by the caller's exit code)
		// and returned so the caller still sets a non-zero status.
		e.printf("%v\n", err)
		return err
	}
	lane := "org-API"
	if req.UseSubscription {
		lane = "subscription"
	}
	e.printf("session %s: launching (%s lane, branch %s)...\n", req.SessionID, lane, req.Branch)
	sum, runErr := runner.Run(ctx, req)
	if runErr != nil {
		e.printf("session %s: FAILED: %v\n", req.SessionID, runErr)
		return runErr
	}
	renderSummary(e, req.SessionID, sum, ev)
	return e.err
}

// renderSummary writes the human-readable review of a completed session.
func renderSummary(e *errWriter, id interfaces.SessionID, sum orchestrator.Summary, ev EvidenceVerifier) {
	e.printf("session %s: inference resolved -> %s\n", id, sum.Inference.URL)
	if sum.HeadSHA == "" {
		e.printf("session %s: no change proposed (clean tree)\n", id)
	} else {
		e.printf("session %s: PROPOSED commit %s (%s) signed by NHI %s\n",
			id, shortSHA(sum.HeadSHA), fileCount(sum.FilesChanged), sum.NHI)
	}
	if sum.PR.URL != "" {
		e.printf("session %s:   PR: %s\n", id, sum.PR.URL)
	}
	if ev == nil {
		e.printf("session %s: evidence: %d records sealed\n", id, sum.Records)
		return
	}
	if err := ev.VerifyChain(); err != nil {
		e.printf("session %s: evidence chain INVALID: %v\n", id, err)
		return
	}
	// Beyond hash-chain integrity, verify every record's per-record lineage signature (human → NHI →
	// action at its real chain position). This is the check a forged/replayed record fails — the
	// chain hash alone is recomputable without a secret.
	if err := ev.VerifyLineage(orchestrator.VerifyRecordPayload); err != nil {
		e.printf("session %s: evidence LINEAGE INVALID: %v\n", id, err)
		return
	}
	e.printf("session %s: evidence chain + lineage VERIFIED (%d records)\n", id, sum.Records)
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func fileCount(files []string) string {
	if len(files) == 1 {
		return "1 file"
	}
	return fmt.Sprintf("%d files", len(files))
}
