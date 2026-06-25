// Command console7-tripwire is the operate-lane PreToolUse mutating-command tripwire (DESIGN.md
// §5.4). The base image installs it at policyhelper.TripwirePath and the operate managed-settings
// wire it on the Bash matcher. It reads the hook payload from stdin (robust JSON parse, not a
// regex), denies an attempted mutating command in-sandbox (exit 2), and marks it as an incident.
// DEFENCE-IN-DEPTH, fail-closed — the authoritative control is the operate session's read-only IAM
// identity. (Emitting the incident to the WORM evidence sink lands when the engine is wired into the
// orchestrator; here the deny + the stderr marker are the live half.)
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/console7/console7/sandbox/policyhelper"
)

// maxHookInput bounds the PreToolUse payload the tripwire will read. A real payload is a few KB; the
// cap stops a compromised/MITM'd inference backend from steering the engine to emit a giant tool-call
// that an unbounded read would let OOM the sandbox.
const maxHookInput = 1 << 20 // 1 MiB

// hookInput is the subset of the Claude Code PreToolUse hook payload the tripwire needs.
type hookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

func main() { os.Exit(run(os.Stdin, os.Stderr)) }

// run reads a PreToolUse payload from stdin and returns the hook exit code: 0 ALLOW, 2 DENY (DENY
// blocks the tool call and feeds stderr back to the model). Fail-closed: an unreadable/unparseable
// payload or an empty command is denied (operate is read-only, so denying on uncertainty is safe).
func run(stdin io.Reader, stderr io.Writer) int {
	// Bound the read (LimitReader): an unbounded io.ReadAll on attacker-influenced stdin is an OOM
	// vector. Read one byte past the cap so we can tell "exactly at cap" from "over".
	data, err := io.ReadAll(io.LimitReader(stdin, maxHookInput+1))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "console7-tripwire: cannot read hook input; denying (fail closed)")
		return 2
	}
	if int64(len(data)) > maxHookInput {
		_, _ = fmt.Fprintln(stderr, "console7-tripwire: hook input exceeds 1 MiB; denying (fail closed)")
		return 2
	}
	var in hookInput
	if err := json.Unmarshal(data, &in); err != nil || in.ToolInput.Command == "" {
		_, _ = fmt.Fprintln(stderr, "console7-tripwire: unparseable hook input or empty command; denying (operate is read-only, fail closed)")
		return 2
	}
	if mutating, matched := policyhelper.IsMutating(in.ToolInput.Command); mutating {
		_, _ = fmt.Fprintf(stderr, "console7-incident: operate-lane mutating command DENIED in-sandbox (matched %q): %s\n", matched, in.ToolInput.Command)
		return 2
	}
	return 0
}
