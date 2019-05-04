package urlutil // import "github.com/pomerium/pomerium/internal/urlutil"

import "testing"

func Test_StripPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		hostport string
		want     string
	}{
		{"localhost", "localhost", "localhost"},
		{"localhost with port", "localhost:443", "localhost"},
		{"IPv6 localhost", "[::1]:80", "::1"},
		{"IPv6 localhost without port", "[::1]", "::1"},
		{"domain with port", "example.org:8080", "example.org"},
		{"domain without port", "example.org", "example.org"},
		{"long domain with port", "some.super.long.domain.example.org:8080", "some.super.long.domain.example.org"},
		{"IPv6 with port", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:17000", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"IPv6 without port", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripPort(tt.hostport); got != tt.want {
				t.Errorf("StripPort() = %v, want %v", got, tt.want)
			}
		})
	}
}
