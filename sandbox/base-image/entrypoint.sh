#!/bin/sh
# Console7 sandbox entrypoint — launches the genuine, pinned Claude Code engine as the non-root
# sandbox user.
#
# The LOCKED managed-settings + hooks are rendered CONTROL-SIDE (the policyhelper package /
# console7-policyhelper binary) from the session's resolved SessionProfile and injected READ-ONLY at
# C7_MANAGED_SETTINGS before this runs. This process is the untrusted agent; it does NOT render its
# own policy. It FAILS CLOSED if the locked settings are absent — the engine never runs without the
# policy that constrains it. (Standalone / local dogfood: render them first, as root, with
# `console7-policyhelper <session-profile.json>`, then start the engine.)
set -eu

# Check the engine's OWN fixed managed-settings location (NOT an overridable env var), so the
# fail-closed guard validates exactly the file the engine will read — a repointed env can't make the
# check pass against a different path than the engine loads.
MANAGED_SETTINGS=/etc/claude-code/managed-settings.json

if [ ! -f "$MANAGED_SETTINGS" ]; then
	echo "console7: locked managed-settings missing at ${MANAGED_SETTINGS} — refusing to start the engine without its policy (fail closed)" >&2
	exit 1
fi

exec claude "$@"
