#!/usr/bin/env bash
#
# PreToolUse(Bash) guard for Console7 — defence-in-depth enforcement of the
# Console7 Repository SDLC Standard (docs/standards/console7-sdlc-standard.md).
#
# This is an IN-BAND guard (tenet 2): a convenience layer that makes a Claude
# session observe the standard by default. The AUTHORITATIVE controls are the CI
# gates and branch protection — this hook only catches the obvious violations
# early, in-session, before they cost a round-trip.
#
# Protocol: read the tool call as JSON on stdin; exit 2 to BLOCK (stderr is
# returned to the agent as the reason); exit 0 to allow. Fail-open on parse
# error (never wedge a session over a guard bug) — CI is the backstop.
#
# Caveat: the guard scans the WHOLE command string, so a pattern carried as data
# (e.g. inside a `git commit -m "…npm install…"` message) can false-positive.
# Pass commit messages via a file — `git commit -S -s -F <file>` — which is the
# repo convention anyway; the guard then only sees the harmless `-F <path>`.

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
# Supply chain (CO-5, CO-8, CO-12.7)
# ---------------------------------------------------------------------------

# Remote script piped into a shell — the classic install-time RCE vector.
# Require an actual URL/IP between the fetch and the pipe-to-shell so that prose
# mentioning the pattern (commit messages, docs) does not false-positive.
if printf '%s' "$cmd" | grep -Eq '(curl|wget)\b[^|]*(https?://|ftp://|[0-9]{1,3}(\.[0-9]{1,3}){3})[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh\b'; then
  block "CO-5/CO-8" "piping a remote script into a shell is prohibited. Download it, review it, pin it, then run it."
fi

# Package installs must route through Socket Firewall (sfw) or be lockfile-faithful.
if printf '%s' "$cmd" | grep -Eq '(^|[;&|`(]|[[:space:]])(npm[[:space:]]+(i|install|add)|pnpm[[:space:]]+(install|add)|yarn[[:space:]]+add|npx|bunx?|pip3?[[:space:]]+install|poetry[[:space:]]+add|uv[[:space:]]+(add|pip)|gem[[:space:]]+install)'; then
  if printf '%s' "$cmd" | grep -Eq '(^|[;&|`(]|[[:space:]])sfw[[:space:]]'; then
    :   # already routed through Socket Firewall
  elif printf '%s' "$cmd" | grep -Eq 'npm[[:space:]]+ci\b|--frozen-lockfile|--immutable|--require-hashes'; then
    :   # lockfile-faithful, no floating resolution
  elif printf '%s' "$cmd" | grep -Eq '@socketsecurity|[[:space:]]sfw($|[[:space:]@])'; then
    :   # bootstrapping the Socket tooling itself
  else
    block "CO-5/CO-12.7" "route dependency installs through Socket Firewall — prefix with 'sfw', or use a lockfile-faithful install (npm ci / --frozen-lockfile). See .claude/skills/supply-chain-policy/SKILL.md."
  fi
fi

# Floating Go installs — pin to a released version; never @latest/@main.
if printf '%s' "$cmd" | grep -Eq 'go[[:space:]]+(get|install)\b[^&|;]*@(latest|main|master|HEAD)\b'; then
  block "CO-5.5" "pin Go dependencies to a released version (no @latest/@main/@HEAD); update go.mod, commit go.sum, and run govulncheck."
fi

# ---------------------------------------------------------------------------
# Change control (CO-4) — the PR-only, signed, DCO workflow
# ---------------------------------------------------------------------------

if printf '%s' "$cmd" | grep -Eq '(^|[;&|`(]|[[:space:]])git[[:space:]]+push\b'; then
  # No direct push to main.
  if printf '%s' "$cmd" | grep -Eq '(origin[[:space:]]+(HEAD:)?main\b|:[[:space:]]*main\b|[[:space:]]main[[:space:]]*$)'; then
    block "CO-4.1/4.4" "no direct push to main — open a feature branch and a PR (CLAUDE.md: 'Never commit to main directly')."
  fi
  # No force-push that touches main.
  if printf '%s' "$cmd" | grep -Eq '(--force\b|--force-with-lease\b|[[:space:]]-f\b)' && printf '%s' "$cmd" | grep -Eq '\bmain\b'; then
    block "CO-4.1" "force-push to main is prohibited (protected, linear history)."
  fi
fi

# DCO sign-off on every commit (CO-4; the inbound-IP control).
if printf '%s' "$cmd" | grep -Eq '(^|[;&|`(]|[[:space:]])git[[:space:]]+commit\b' \
   && ! printf '%s' "$cmd" | grep -Eq '(--amend|--no-edit)\b'; then
  if ! printf '%s' "$cmd" | grep -Eq '(--signoff\b|(^|[[:space:]])-[A-Za-z]*s[A-Za-z]*([[:space:]]|$))'; then
    block "CO-4 (DCO)" "commits must carry a DCO sign-off and be signed: use 'git commit -S -s -m \"…\"'. See CONTRIBUTING / the SDLC standard CO-4."
  fi
fi

exit 0
