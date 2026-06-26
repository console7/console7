package scmgithub

import "testing"

// TestExpectedHostFromBaseURL pins the BaseURL validation: github.com by default, the GHES host for
// a valid https base, and fail-closed for cleartext / credential-bearing / malformed values. The
// http:// case is the security fix — ghinstallation would otherwise POST the App JWT in cleartext.
func TestExpectedHostFromBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		want    string
		wantErr bool
	}{
		{"default github.com", "", DefaultExpectedHost, false},
		{"valid GHES https", "https://ghe.example.com/api/v3/", "ghe.example.com", false},
		{"http rejected", "http://ghe.example.com/api/v3/", "", true},
		{"userinfo rejected", "https://user:pw@ghe.example.com/api/v3/", "", true},
		{"no host rejected", "https:///api/v3/", "", true},
		{"garbage rejected", "://nope", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expectedHostFromBaseURL(tc.baseURL)
			if (err != nil) != tc.wantErr {
				t.Fatalf("expectedHostFromBaseURL(%q) err=%v, wantErr=%v", tc.baseURL, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("expectedHostFromBaseURL(%q) = %q, want %q", tc.baseURL, got, tc.want)
			}
		})
	}
}
