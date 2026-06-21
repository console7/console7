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
// operate-lane PreToolUse tripwire (DESIGN.md §5.4). It is DEFENCE-IN-DEPTH, NOT the control of
// record — the operate session's read-only cloud identity (IAM) is. Its job here is the local-FS /
// in-sandbox mutation class (which IAM does not cover) and surfacing the attempt.
//
// It is deliberately robust against the ways an agent chains commands — it splits on shell
// separators (; | & newline, subshells) so a verb after any of them is still examined, strips
// leading wrappers (sudo/xargs/env/...), matches a denylisted verb only at COMMAND POSITION (so
// "grep rm file" is NOT flagged but "rm file" and "true; rm file" are), and treats a write
// redirection as mutating. It returns the matched token for the incident message. Heuristic, not
// exhaustive; the caller fails closed on an empty/unparseable command.
func IsMutating(command string) (bool, string) {
	if command == "" {
		return false, ""
	}
	// A write redirection anywhere is a file mutation (operate is read-only). Match ">"/">>" but not
	// fd-duplication like "2>&1" (the char after > is "&") or input "<".
	if hasWriteRedirect(command) {
		return true, ">"
	}
	for _, seg := range splitSegments(command) {
		if mutating, matched := segmentMutates(seg); mutating {
			return true, matched
		}
	}
	return false, ""
}

// segmentMutates checks one command segment (already separator-free): strips leading wrappers,
// then matches a denylisted verb / tool-subcommand / mutating find at command position.
func segmentMutates(seg string) (bool, string) {
	toks := stripWrappers(strings.Fields(seg))
	if len(toks) == 0 {
		return false, ""
	}
	verb := path.Base(toks[0]) // basename so /bin/rm matches rm
	if mutatingVerbs[verb] {
		return true, verb
	}
	if len(toks) >= 2 && mutatingSubcommands[verb+" "+toks[1]] {
		return true, verb + " " + toks[1]
	}
	// find is read-only EXCEPT with -delete / -exec / -execdir.
	if verb == "find" {
		for _, t := range toks[1:] {
			if t == "-delete" || t == "-exec" || t == "-execdir" {
				return true, "find " + t
			}
		}
	}
	return false, ""
}

// splitSegments breaks a command into the chunks between shell command separators and grouping
// (NOT spaces, NOT redirections), so each chunk's first token is a command in command position.
func splitSegments(command string) []string {
	return strings.FieldsFunc(command, func(r rune) bool {
		switch r {
		case ';', '|', '&', '\n', '\r', '(', ')', '{', '}', '`':
			return true
		}
		return false
	})
}

// stripWrappers drops leading command wrappers that pass through to a real command, so the verb
// after them is examined (e.g. "sudo rm", "xargs rm", "env FOO=1 rm").
func stripWrappers(toks []string) []string {
	for len(toks) > 0 {
		switch path.Base(toks[0]) {
		case "sudo", "xargs", "env", "nice", "ionice", "nohup", "timeout", "command", "builtin", "exec", "time", "doas":
			toks = toks[1:]
			// env/timeout/nice take options/assignments/durations before the real command; skip
			// non-command-ish leading tokens (an =assignment, a -flag, or a number/duration like the
			// "5" in `timeout 5 rm`) until the next bare command word — a command never starts with a digit.
			for len(toks) > 0 && isWrapperArg(toks[0]) {
				toks = toks[1:]
			}
		default:
			return toks
		}
	}
	return toks
}

// isWrapperArg reports whether a token is an argument to a leading wrapper (assignment, flag, or a
// number/duration), not the wrapped command — a real command never starts with a digit.
func isWrapperArg(tok string) bool {
	if tok == "" {
		return true
	}
	return strings.Contains(tok, "=") || tok[0] == '-' || (tok[0] >= '0' && tok[0] <= '9')
}

// hasWriteRedirect reports whether the command writes to a file via > or >> (not 2>&1 / >& fd dup,
// not input <).
func hasWriteRedirect(command string) bool {
	for i := 0; i < len(command); i++ {
		if command[i] != '>' {
			continue
		}
		// ">>" is still a write; skip the second '>'.
		j := i + 1
		if j < len(command) && command[j] == '>' {
			j++
		}
		// fd duplication ">&" / ">&1" is not a file write.
		if j < len(command) && command[j] == '&' {
			i = j
			continue
		}
		return true
	}
	return false
}

// mutatingVerbs are single-word commands that mutate at command position.
var mutatingVerbs = map[string]bool{
	"rm": true, "rmdir": true, "mv": true, "cp": true, "dd": true, "truncate": true,
	"tee": true, "chmod": true, "chown": true, "chgrp": true, "ln": true, "install": true,
	"mkfs": true, "shred": true, "shutdown": true, "reboot": true, "halt": true, "poweroff": true,
	"kill": true, "killall": true, "pkill": true, "mount": true, "umount": true, "crontab": true,
}

// mutatingSubcommands are "<tool> <subcommand>" pairs that mutate (the tool alone is read-only).
var mutatingSubcommands = map[string]bool{
	"kubectl delete": true, "kubectl apply": true, "kubectl edit": true, "kubectl patch": true,
	"kubectl scale": true, "kubectl create": true, "kubectl replace": true, "kubectl rollout": true,
	"kubectl drain": true, "kubectl cordon": true, "kubectl annotate": true, "kubectl label": true,
	"terraform apply": true, "terraform destroy": true, "terraform import": true, "terraform state": true,
	"terraform taint": true,
	"gsutil rm":       true, "gsutil cp": true, "gsutil mv": true,
	"systemctl start": true, "systemctl stop": true, "systemctl restart": true, "systemctl disable": true, "systemctl enable": true,
	"git push": true, "git commit": true, "git merge": true, "git reset": true, "git rebase": true, "git clean": true,
	"docker run": true, "docker rm": true, "docker rmi": true, "docker exec": true,
	"sed -i":     true,
	"apt remove": true, "apt-get remove": true, "apt install": true, "apt-get install": true,
	"npm install": true, "pip install": true, "go install": true,
}
