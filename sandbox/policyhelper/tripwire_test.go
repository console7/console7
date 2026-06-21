package policyhelper

import "testing"

func TestIsMutating(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		// read-only — must NOT be flagged
		{"", false},
		{"ls -la", false},
		{"cat platform.txt", false}, // "platform" must not match " rm "
		{"grep rm file.txt", false}, // rm as an ARG to grep, not command position
		{"terraform plan", false},   // plan is read-only
		{"kubectl get pods", false}, // get is read-only
		{"kubectl describe pod x", false},
		{"git log --oneline", false},
		{"git status", false},
		{"find . -name '*.go'", false}, // find without -delete/-exec
		{"echo performing a move", false},
		{"gcloud compute instances list", false},
		{"aws s3 ls", false},

		// direct mutating commands
		{"rm -rf /tmp/x", true},
		{"/bin/rm -rf /tmp/x", true}, // basename
		{"mv a b", true},
		{"cp a b", true},
		{"truncate -s0 f", true},
		{"chmod +x f", true},
		{"terraform apply -auto-approve", true},
		{"kubectl delete ns x", true},
		{"git push origin main", true},
		{"git commit -am x", true},
		{"find . -name x -delete", true},
		{"find . -exec rm {} +", true},

		// CHAINING / separators — the bypasses the review found, must all be caught
		{"true; rm -rf /etc", true},
		{"true;rm -rf /etc", true},
		{"true && rm -rf /etc", true},
		{"true&&rm -rf /etc", true},
		{"cat x | rm", true},
		{"(rm -rf /etc)", true},
		{"echo hi\nrm -rf /etc\necho bye", true},
		{"ls | xargs rm", true},    // wrapper passthrough
		{"sudo rm -rf /etc", true}, // wrapper passthrough
		{"env FOO=1 rm x", true},   // wrapper + assignment
		{"timeout 5 rm x", true},   // wrapper + option

		// redirection (file write) — operate is read-only
		{"echo data > /etc/passwd", true},
		{"echo data >> /etc/passwd", true},
		{"echo x >| /etc/passwd", true},
		{"kubectl get pods 2>&1", false}, // fd-dup, not a file write

		// redirect FALSE POSITIVES that must stay read-only (the review caught these)
		{`echo "a > b"`, false},      // > inside double quotes
		{`grep '>' file.txt`, false}, // > inside single quotes
		{"cat a->b.txt", false},      // -> arrow, not a redirect
		{"git log --format=%h", false},

		// shell / interpreter ESCAPE primitives — the big bypass class, must be caught
		{`bash -c "rm -rf /etc"`, true},
		{`sh -c 'rm -rf /etc'`, true},
		{`bash -c "echo hi"`, false}, // recurse: read-only payload is allowed
		{"eval rm -rf /etc", true},
		{`python -c "import os; os.remove('x')"`, true},
		{`python3 -c "..."`, true},
		{"perl -e unlink", true},
		{"node -e x", true},
		{"echo x | sh", true}, // pipe to a bare subshell
		{"cat script | bash", true},
		{"python analyze.py", false}, // running a script file is not inline-eval

		// global flag BEFORE the subcommand must not defeat the subcommand table
		{"kubectl --context prod delete ns x", true},
		{"kubectl -n ns delete pod x", true},
		{"git -C /repo push", true},
		{"terraform -chdir=/r apply", true},
		{"docker -H tcp://x run img", true},
		{"sudo -u root rm x", true}, // wrapper value-flag must not swallow the command
		{"FOO=1 rm x", true},        // bare inline assignment prefix
		{"helm upgrade rel chart", true},
		{"aws s3 ls", false}, // cloud read-only — IAM-covered, not a tripwire false-positive
		{"kubectl get pods -o yaml", false},
	}
	for _, tc := range cases {
		got, matched := IsMutating(tc.cmd)
		if got != tc.want {
			t.Errorf("IsMutating(%q) = %v (matched %q), want %v", tc.cmd, got, matched, tc.want)
		}
	}
}
