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
		{"kubectl get pods 2>&1", false}, // fd-dup, not a file write
	}
	for _, tc := range cases {
		got, matched := IsMutating(tc.cmd)
		if got != tc.want {
			t.Errorf("IsMutating(%q) = %v (matched %q), want %v", tc.cmd, got, matched, tc.want)
		}
	}
}
