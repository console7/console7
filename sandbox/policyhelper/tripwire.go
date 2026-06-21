package policyhelper

import (
	"path"
	"strings"
)

// TripwirePath is where the base image installs the compiled mutating-command tripwire binary
// (sandbox/policyhelper/cmd/tripwire). The operate lane's PreToolUse hook invokes it; the engine
// runtime needs nothing but the binary, which is baked in the image. (Composed from parts so gosec
// G101 doesn't false-positive a binary path as a hardcoded credential.)
var TripwirePath = binDir + "/console7-tripwire"

const binDir = "/usr/local/bin"

// IsMutating heuristically reports whether a shell command attempts a mutating operation, for the
// operate-lane PreToolUse tripwire (DESIGN.md §5.4). It is BEST-EFFORT DEFENCE-IN-DEPTH, NOT a
// reliable control. For CLOUD mutations the authoritative control is the operate session's
// read-only IAM identity; for LOCAL-FS mutations the authoritative control is the read-only /
// ephemeral workspace mount (a sandbox-runtime boundary control — DESIGN.md §5.1; landed with the
// engine wiring, not in this PR). This heuristic surfaces the attempt and blocks the cheap cases.
//
// It tokenizes quote-aware (so a "> b" inside a quoted string is NOT a redirect, and `bash -c "rm
// x"` is examined), splits on unquoted shell separators (so a verb after ; && | newline subshell is
// caught at command position), strips leading inline `VAR=val` assignments and wrappers
// (sudo/xargs/env/timeout), recurses into `sh -c`/`eval` payloads, denies interpreter inline-eval
// and bare subshells outright (an escape primitive a read-only session does not need), and matches a
// tool subcommand past its global flags. KNOWN RESIDUAL BYPASSES (heuristic limits — the read-only
// mount is the backstop): command substitution `$(...)`/backticks, encoded payloads piped to a
// shell, and novel interpreters. Returns the matched token for the incident message.
func IsMutating(command string) (bool, string) {
	if strings.TrimSpace(command) == "" {
		return false, ""
	}
	segments, redirect := shellScan(command)
	if redirect {
		return true, ">"
	}
	for _, toks := range segments {
		if mutating, matched := segmentMutates(toks); mutating {
			return true, matched
		}
	}
	return false, ""
}

// segmentMutates checks one tokenized command segment (separator-free, quotes already stripped).
func segmentMutates(toks []string) (bool, string) {
	toks = stripPrefix(toks)
	if len(toks) == 0 {
		return false, ""
	}
	cmd := path.Base(toks[0]) // basename so /bin/rm matches rm
	args := toks[1:]

	// Subshells and eval: a read-only operate session has no need to spawn a subshell or eval code.
	// Recurse into a `-c` payload if present (so `bash -c "echo hi"` is fine but `bash -c "rm x"` is
	// caught); otherwise deny the bare subshell (reading a script or stdin = run anything).
	if shells[cmd] {
		if payload, ok := dashCArg(args); ok {
			return IsMutating(payload)
		}
		return true, cmd
	}
	if cmd == "eval" {
		return IsMutating(strings.Join(args, " "))
	}
	// Interpreters with inline code (`python -c`, `perl -e`, `node -e`, …): the payload is not shell,
	// so it cannot be re-parsed — deny the inline-eval primitive for the read-only lane.
	if interpreters[cmd] && hasInlineCode(args) {
		return true, cmd + " -c"
	}

	if mutatingVerbs[cmd] {
		return true, cmd
	}
	// Tool subcommand, found PAST the tool's global flags (so `kubectl --context x delete` is caught).
	if sub, ok := firstNonFlag(args); ok && mutatingSubcommands[cmd+" "+sub] {
		return true, cmd + " " + sub
	}
	// find is read-only EXCEPT with -delete / -exec / -execdir.
	if cmd == "find" {
		for _, t := range args {
			if t == "-delete" || t == "-exec" || t == "-execdir" {
				return true, "find " + t
			}
		}
	}
	return false, ""
}

// lexer is a small quote-aware shell-ish tokenizer. shellScan drives it.
type lexer struct {
	segments [][]string
	seg      []string
	tok      strings.Builder
	quote    rune // 0, '\'' or '"'
	hasTok   bool
	redirect bool
}

func (l *lexer) add(r rune) { l.tok.WriteRune(r); l.hasTok = true }

func (l *lexer) flushTok() {
	if l.hasTok {
		l.seg = append(l.seg, l.tok.String())
		l.tok.Reset()
		l.hasTok = false
	}
}

func (l *lexer) flushSeg() {
	l.flushTok()
	if len(l.seg) > 0 {
		l.segments = append(l.segments, l.seg)
		l.seg = nil
	}
}

// unquoted processes one rune outside any quote and returns the (possibly advanced) index.
func (l *lexer) unquoted(runes []rune, i int) int {
	r := runes[i]
	switch r {
	case '\'', '"':
		l.quote = r
		l.hasTok = true
	case '\\':
		if i+1 < len(runes) {
			i++
			l.add(runes[i])
		}
	case ' ', '\t':
		l.flushTok()
	case ';', '|', '&', '\n', '\r', '(', ')', '{', '}', '`':
		l.flushSeg()
	case '<':
		l.flushTok() // input redirect: a token boundary, not mutating
	case '>':
		advance, isRedirect, literal := scanGT(runes, i)
		if literal {
			l.add(r) // "->" arrow, not a redirect
		} else {
			l.redirect = l.redirect || isRedirect
			i += advance
			l.flushTok()
		}
	default:
		l.add(r)
	}
	return i
}

// shellScan splits command into SEGMENTS (separated by unquoted shell command separators ; | &
// newline and subshell grouping) of TOKENS (whitespace-separated, with ' and " quoting and \
// escaping respected and the quotes stripped), and reports whether it contains an unquoted
// file-write redirect (> or >>, not the fd-dup >&). It does NOT expand $(...) / backticks (a
// disclosed residual). A pragmatic shell-ish tokenizer, not a full parser.
func shellScan(command string) (segments [][]string, redirect bool) {
	l := &lexer{}
	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		if l.quote != 0 {
			if runes[i] == l.quote {
				l.quote = 0
			} else {
				l.tok.WriteRune(runes[i])
			}
			l.hasTok = true
			continue
		}
		i = l.unquoted(runes, i)
	}
	l.flushSeg()
	return l.segments, l.redirect
}

// scanGT classifies a '>' at index i: a "->" arrow (literal, kept in the token), or a file-write
// redirect — unless it is a fd-dup (>&). advance is the extra runes the redirect token consumed
// (for ">>"); the caller adds it to i.
func scanGT(runes []rune, i int) (advance int, isRedirect, literal bool) {
	if i > 0 && runes[i-1] == '-' {
		return 0, false, true
	}
	j := i + 1
	if j < len(runes) && runes[j] == '>' {
		j++
	}
	isRedirect = j >= len(runes) || runes[j] != '&' // a write redirect, not a >& fd-dup
	return j - 1 - i, isRedirect, false
}

// stripPrefix drops leading inline `VAR=val` assignments and command wrappers (sudo/xargs/env/...)
// so the real command is examined. For a wrapper that takes a value flag (sudo -u USER), the value
// is also skipped.
func stripPrefix(toks []string) []string {
	for len(toks) > 0 {
		t := toks[0]
		// inline environment assignment prefix: FOO=bar cmd
		if isAssignment(t) {
			toks = toks[1:]
			continue
		}
		w := path.Base(t)
		if !wrappers[w] {
			return toks
		}
		toks = toks[1:]
		// skip the wrapper's options/assignments/values until the next bare command word.
		for len(toks) > 0 && isWrapperArg(toks[0]) {
			// a value-taking flag like `-u` / `--user` consumes the NEXT token too.
			if valueFlags[toks[0]] && len(toks) >= 2 {
				toks = toks[2:]
				continue
			}
			toks = toks[1:]
		}
	}
	return toks
}

// firstNonFlag returns the first token that is not a flag/flag-value/assignment — a tool's
// subcommand sits there even past global flags (e.g. `kubectl --context x delete` -> "delete").
// Value-taking flags consume their following value so it is not mistaken for the subcommand.
func firstNonFlag(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if valueFlags[a] {
			i++ // skip the flag's value
			continue
		}
		if strings.HasPrefix(a, "-") || isAssignment(a) {
			continue
		}
		return a, true
	}
	return "", false
}

func isAssignment(t string) bool {
	eq := strings.IndexByte(t, '=')
	return eq > 0 && !strings.HasPrefix(t, "-")
}

// isWrapperArg reports whether a token is an argument to a leading wrapper (assignment, flag, or a
// number/duration), not the wrapped command — a real command never starts with a digit.
func isWrapperArg(tok string) bool {
	if tok == "" {
		return true
	}
	return isAssignment(tok) || tok[0] == '-' || (tok[0] >= '0' && tok[0] <= '9')
}

// dashCArg returns the argument after a `-c` flag (a shell command payload), if present.
func dashCArg(args []string) (string, bool) {
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// hasInlineCode reports whether an interpreter is invoked with inline code (-c/-e/-E) rather than a
// script file.
func hasInlineCode(args []string) bool {
	for _, a := range args {
		if a == "-c" || a == "-e" || a == "-E" {
			return true
		}
	}
	return false
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true}

var interpreters = map[string]bool{
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true, "php": true,
}

var wrappers = map[string]bool{
	"sudo": true, "xargs": true, "env": true, "nice": true, "ionice": true, "nohup": true,
	"timeout": true, "command": true, "builtin": true, "exec": true, "time": true, "doas": true,
	"stdbuf": true, "setsid": true,
}

// valueFlags are wrapper/tool flags that consume the following token as their value.
var valueFlags = map[string]bool{
	"-u": true, "--user": true, "-n": true, "--nice": true, "-I": true, "-i": true,
	"--signal": true, "-s": true, "-C": true, "--context": true, "--namespace": true, "-H": true,
	"-chdir": true, "--prefix": true,
}

// mutatingVerbs are single-word commands that mutate at command position.
var mutatingVerbs = map[string]bool{
	"rm": true, "rmdir": true, "mv": true, "cp": true, "dd": true, "truncate": true,
	"tee": true, "chmod": true, "chown": true, "chgrp": true, "ln": true, "install": true,
	"mkfs": true, "shred": true, "shutdown": true, "reboot": true, "halt": true, "poweroff": true,
	"kill": true, "killall": true, "pkill": true, "mount": true, "umount": true, "crontab": true,
	"tar": true, "unzip": true,
	// File creators: the operate lane denies Edit/Write, so these are the Bash route to creating or
	// stamping in-sandbox files (the read-only/ephemeral workspace mount is the authoritative block).
	"touch": true, "mkdir": true, "mknod": true, "mkfifo": true, "mktemp": true, "patch": true,
}

// mutatingSubcommands are "<tool> <subcommand>" pairs that mutate (the tool alone is read-only).
var mutatingSubcommands = map[string]bool{
	"kubectl delete": true, "kubectl apply": true, "kubectl edit": true, "kubectl patch": true,
	"kubectl scale": true, "kubectl create": true, "kubectl replace": true, "kubectl rollout": true,
	"kubectl drain": true, "kubectl cordon": true, "kubectl annotate": true, "kubectl label": true,
	"terraform apply": true, "terraform destroy": true, "terraform import": true, "terraform state": true,
	"terraform taint": true,
	"gsutil rm":       true, "gsutil cp": true, "gsutil mv": true,
	"git push": true, "git commit": true, "git merge": true, "git reset": true, "git rebase": true, "git clean": true,
	"docker run": true, "docker rm": true, "docker rmi": true, "docker exec": true, "docker build": true,
	"podman run": true, "podman rm": true,
	"helm install": true, "helm upgrade": true, "helm delete": true, "helm uninstall": true, "helm rollback": true,
	"npm install": true, "pip install": true, "go install": true,
	"systemctl start": true, "systemctl stop": true, "systemctl restart": true, "systemctl disable": true, "systemctl enable": true,
	// NOTE: deliberately NOT listing aws/gcloud cloud-CLI mutators — those are CLOUD mutations the
	// operate session's read-only IAM identity already blocks authoritatively (DESIGN.md §5.4), and
	// their 3-level `aws <svc> <action>` shape would false-positive read-only calls like `aws s3 ls`.
}
