#!/usr/bin/env bash
#
# CO-12.7 / CO-12.8 governance gate — agentic-artifact supply-chain provenance.
#
# Console7's .claude/ skills, agents, commands, and hooks are CODE and must be
# FIRST-PARTY / SELF-AUTHORED. This gate fails closed if any in-repo agentic
# artifact:
#   (a) is a symlink pointing outside the repository, or
#   (b) declares or references a remote / marketplace source (a live fetch).
# A governance gate that cannot fail is worthless: any violation -> exit 1.
#
# Runs in CI (see .github/workflows/governance-gate.yml). No network, no deps
# beyond coreutils + grep. Deterministic.

set -uo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

fail=0
checked=0
err() { printf '  ✗ %s\n' "$1"; fail=1; }

# A reference that indicates a remote/marketplace source rather than self-authored.
# Matches: source:/marketplace:/plugin: keys pointing at a URL or git host, or any
# raw git/clone URL embedded in an agentic artifact.
remote_re='(^|[[:space:]"'"'"'])(source|marketplace|plugin|repository|url)[[:space:]]*[:=][[:space:]]*["'"'"']?(https?://|git@|git\+|ssh://|github\.com[:/]|gitlab\.com|bitbucket\.org)'
clone_re='git[[:space:]]+clone[[:space:]]+(https?://|git@)'

# Scan EVERY file and symlink under .claude/ — skills (directory SKILL.md and
# flat .md), agents, commands, hooks, settings.json, supporting/helper files, and
# any plugin/marketplace manifests. Broad by design: a remote source in a helper
# file or settings.json, or a symlink to outside-repo code, is just as much a
# provenance breach as one in a SKILL.md. Symlinks are enumerated explicitly
# (-type l) so the target check runs — a plain -type f would never emit them.
# Portable to bash 3.2 (no mapfile): process substitution keeps the loop in the
# current shell so counters persist.
while IFS= read -r f; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  checked=$((checked + 1))

  # (a) symlink — verify its target stays inside the repo, then move on (a
  #     symlink has no text body of its own to grep).
  if [ -L "$f" ]; then
    target="$(readlink "$f")"
    case "$target" in
      /*|*../*) err "$f is a symlink to '$target' (outside-repo source prohibited)";;
    esac
    continue
  fi

  # (b) remote/marketplace source reference
  if grep -Eiq "$remote_re" "$f" 2>/dev/null; then
    err "$f references a remote/marketplace source (must be first-party/self-authored)"
  fi
  if grep -Eiq "$clone_re" "$f" 2>/dev/null; then
    err "$f embeds a 'git clone <url>' (live fetch of agentic code prohibited)"
  fi
done < <(
  # settings.local.json is per-user and gitignored (never committed), so it is
  # out of scope for a committed-artifact provenance gate.
  find .claude \( -type f -o -type l \) ! -name 'settings.local.json' 2>/dev/null | sort -u
)

printf 'CO-12.7 provenance: checked %d agentic artifact(s).\n' "$checked"
if [ "$fail" -ne 0 ]; then
  printf 'FAIL — first-party/self-authored only. See docs/standards/console7-sdlc-standard.md CO-12.7.\n'
  exit 1
fi
printf 'PASS — all agentic artifacts are first-party/self-authored.\n'
exit 0
