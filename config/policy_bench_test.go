package config

import (
	"testing"
)

// BenchmarkPolicyChecksum measures Policy.Checksum() on a single, realistic
// policy. Checksum currently walks the struct via reflection
// (hashutil.MustHash -> mitchellh/hashstructure) on every call, so this is
// the baseline a future memoized implementation should beat.
func BenchmarkPolicyChecksum(b *testing.B) {
	p := &Policy{
		From: "https://from.example.com",
		To:   mustParseWeightedURLs(b, "https://to.example.com"),
		AllowedUsers: []string{
			"user1@example.com",
			"user2@example.com",
		},
		AllowedDomains: []string{
			"example.com",
			"other-example.com",
		},
		SetRequestHeaders: map[string]string{
			"X-Custom-Header-1": "value1",
			"X-Custom-Header-2": "value2",
		},
		PrefixRewrite:      "/rewritten",
		HostRewrite:        "internal.example.com",
		PreserveHostHeader: false,
		AllowWebsockets:    true,
		TLSSkipVerify:      false,
	}
	if err := p.Validate(); err != nil {
		b.Fatalf("policy failed validation: %v", err)
	}

	b.ReportAllocs()
	var sink uint64
	for b.Loop() {
		sink = p.Checksum()
	}
	_ = sink
}
