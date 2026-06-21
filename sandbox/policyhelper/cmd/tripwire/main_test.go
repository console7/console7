package main

import (
	"io"
	"strings"
	"testing"
)

func TestRun_HookExitCodes(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    int
	}{
		{"read-only allowed", `{"tool_name":"Bash","tool_input":{"command":"kubectl get pods"}}`, 0},
		{"mutating denied", `{"tool_name":"Bash","tool_input":{"command":"kubectl delete ns x"}}`, 2},
		{"chained mutation denied", `{"tool_name":"Bash","tool_input":{"command":"true; rm -rf /etc"}}`, 2},
		// the real payload has a description AFTER command — must still parse + allow a read-only cmd
		{"command not last field", `{"tool_input":{"command":"ls -la","description":"list, then maybe delete"}}`, 0},
		// ...and still catch a real mutation even with a trailing description
		{"mutation with description", `{"tool_input":{"command":"rm -rf /etc","description":"clean up"}}`, 2},
		{"unparseable denied", `not json`, 2},
		{"empty command denied", `{"tool_input":{"command":""}}`, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(strings.NewReader(tc.payload), io.Discard); got != tc.want {
				t.Errorf("run(%s) = %d, want %d", tc.payload, got, tc.want)
			}
		})
	}
}
