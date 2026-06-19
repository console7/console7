#!/usr/bin/env bash
#
# PreToolUse(Bash) guard for Console7 — defence-in-depth enforcement of the
# Console7 Repository SDLC Standard (docs/standards/console7-sdlc-standard.md).
#
# This is an IN-BAND guard (tenet 2): a convenience layer that makes a Claude
# session observe the standard by default. The AUTHORITATIVE controls are the CI
# gates and branch protection (e.g. required signed commits is enforced
# server-side, not here) — this hook only catches obvious violations early.
#
# Protocol: read the tool call as JSON on stdin; exit 2 to BLOCK (stderr is
# returned to the agent as the reason); exit 0 to allow. Fail-open on parse
# error (never wedge a session over a guard bug) — CI is the backstop.
#
# Caveat: the guard scans the command string, so a pattern carried as data
# (e.g. inside a `git commit -m "…npm install…"` message) can false-positive.
# Pass commit messages via a file — `git commit -S -s -F <file>` — the repo
# convention; the guard then only sees the harmless `-F <path>`.

set -uo pipefail

input="$(cat)"
cmd="$(printf '%s' "$input" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("tool_input", {}).get("command", ""))
except Exception:
    print("")
' 2>/dev/null)"

[ -z "$cmd" ] && exit 0

block() { printf 'BLOCKED by Console7 SDLC guard (%s): %s\n' "$1" "$2" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Whole-command checks — the pipe itself is the vector.
# ---------------------------------------------------------------------------

# Remote script piped into a shell. Requires a real URL/IP so prose does not
# false-positive; tolerates sudo/env wrappers and an absolute path to the shell
# (e.g. `| /bin/sh`, `| env bash`, `| sudo sh`).
if printf '%s' "$cmd" | grep -Eq '(curl|wget)\b[^|]*(https?://|ftp://|[0-9]{1,3}(\.[0-9]{1,3}){3})[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(env[[:space:]]+)?([^[:space:]|]*/)?(ba|z|da|c|fi|tc|k|a)?sh\b'; then
  block "CO-5/CO-8" "piping a remote script into a shell is prohibited. Download it, review it, pin it, then run it."
fi

# ---------------------------------------------------------------------------
# Per-segment supply-chain checks (CO-5, CO-12.7) — split the command on shell
# separators so an allow-token in one segment cannot whitelist an install in
# another (e.g. `sfw --help; npm install evil`).
# ---------------------------------------------------------------------------

segments="$(printf '%s' "$cmd" | sed -E 's/(\&\&|\|\||;|\&|\n)/\n/g')"
while IFS= read -r seg; do
  [ -z "$seg" ] && continue

  # Package install in THIS segment must be Socket-Firewall-routed or
  # lockfile-faithful (or the sfw/Socket bootstrap itself).
  if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])(npm[[:space:]]+(i|install|add)|pnpm[[:space:]]+(install|add)|yarn[[:space:]]+add|npx|bunx?|pip3?[[:space:]]+install|poetry[[:space:]]+add|uv[[:space:]]+(add|pip)|gem[[:space:]]+install)'; then
    if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])sfw[[:space:]]'; then
      :
    elif printf '%s' "$seg" | grep -Eq 'npm[[:space:]]+ci\b|--frozen-lockfile|--immutable|--require-hashes'; then
      :
    elif printf '%s' "$seg" | grep -Eq '@socketsecurity|(^|[[:space:]])sfw($|[[:space:]@])'; then
      :
    else
      block "CO-5/CO-12.7" "route dependency installs through Socket Firewall — prefix with 'sfw', or use a lockfile-faithful install (npm ci / --frozen-lockfile). See .claude/skills/supply-chain-policy/SKILL.md."
    fi
  fi

  # Floating Go installs in THIS segment: explicit @latest/@main, OR a module
  # path with no @version (which `go get`/`go install` resolves to latest).
  if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])go[[:space:]]+(get|install)[[:space:]]'; then
    if printf '%s' "$seg" | grep -Eq '@(latest|main|master|head|upgrade|patch|none)\b'; then
      block "CO-5.5" "pin Go dependencies to a released version (no @latest/@main/@HEAD); update go.mod, commit go.sum, run govulncheck."
    elif printf '%s' "$seg" | grep -Eq 'go[[:space:]]+(get|install)[[:space:]]+([^@[:space:]]*[[:space:]]+)*[a-z0-9.-]+\.[a-z]{2,}/[^@[:space:]]*([[:space:]]|$)'; then
      block "CO-5.5" "pin Go dependencies to a released version — a module path with no @version floats to latest. Use module@vX.Y.Z."
    fi
  fi
done <<EOF
$segments
EOF

# ---------------------------------------------------------------------------
# Change control (CO-4) — PR-only, DCO-signed workflow. (Commit *signing* is
# enforced authoritatively by branch protection's required-signatures, so the
# hook focuses on the DCO leg that branch protection does not cover.)
# ---------------------------------------------------------------------------

if printf '%s' "$cmd" | grep -Eq '(^|[[:space:]])git[[:space:]]+push\b'; then
  # No direct push to main — matches `main` or `refs/heads/main` as a ref token,
  # including `HEAD:main`, `HEAD:refs/heads/main`, `:main`, `:refs/heads/main`.
  if printf '%s' "$cmd" | grep -Eq '(^|[[:space:]:])(refs/heads/)?main([[:space:]]|$)'; then
    block "CO-4.1/4.4" "no direct push to main — open a feature branch and a PR (CLAUDE.md: 'Never commit to main directly')."
  fi
  # No force-push that touches main.
  if printf '%s' "$cmd" | grep -Eq '(--force\b|--force-with-lease\b|[[:space:]]-f\b)' && printf '%s' "$cmd" | grep -Eq '(refs/heads/)?main\b'; then
    block "CO-4.1" "force-push to main is prohibited (protected, linear history)."
  fi
fi

# DCO sign-off on commits. Allow an amend that preserves the message/trailers
# (--no-edit); otherwise require -s/--signoff.
if printf '%s' "$cmd" | grep -Eq '(^|[[:space:]])git[[:space:]]+commit\b'; then
  if printf '%s' "$cmd" | grep -Eq '\-\-amend\b' && printf '%s' "$cmd" | grep -Eq '\-\-no-edit\b'; then
    :
  elif printf '%s' "$cmd" | grep -Eq '(--signoff\b|(^|[[:space:]])-[A-Za-z]*s[A-Za-z]*([[:space:]]|$))'; then
    :
  else
    block "CO-4 (DCO)" "commits must carry a DCO sign-off: add -s (use 'git commit -S -s …'). Signing itself is enforced by branch protection."
  fi
fi

# ---------------------------------------------------------------------------
# Advisory (NON-BLOCKING) — pre-push review reminder. Runs LAST, after every
# blocking check, so it can NEVER pre-empt one (notably the DCO check on a
# combined `git commit … && git push`). It never blocks: "not reviewed" is a
# judgement call, not a violation, and a hard self-review gate would turn an
# in-band check into a false control of record (tenet 2). Emitted as PreToolUse
# additionalContext (static string — no untrusted data interpolated) so the agent
# sees the nudge; control then falls through to the final allow (exit 0).
# ---------------------------------------------------------------------------
if printf '%s' "$cmd" | grep -Eq '(^|[[:space:]])git[[:space:]]+push\b'; then
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  if [ -n "$branch" ] && [ "$branch" != "main" ] && [ "$branch" != "HEAD" ]; then
    changed="$(git diff --name-only main...HEAD 2>/dev/null || true)"
    if [ -n "$changed" ] && printf '%s' "$changed" | grep -qvE '(\.md$|^docs/)'; then
      printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"Console7 pre-push reminder: this feature branch changed non-doc files. For substantive changes, run the pre-pr-review skill (adversarial correctness + security + spec-alignment over the diff) and reconcile findings BEFORE pushing. Defence-in-depth, not a gate; skip for pure docs."}}'
    fi
  fi
fi

exit 0
