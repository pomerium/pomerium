package mcp

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSSRFSafeClient_RefusesRedirects verifies that the SSRF-safe metadata
// client refuses to follow HTTP redirects. This is a core part of the fix:
// following a redirect from an allowlisted origin to an internal host would
// re-open the SSRF the allowlist is meant to close. Pure in-memory, no network.
func TestSSRFSafeClient_RefusesRedirects(t *testing.T) {
	t.Parallel()

	client := NewSSRFSafeClient()
	require.NotNil(t, client.CheckRedirect,
		"SSRF-safe client must install a CheckRedirect hook")

	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)

	err = client.CheckRedirect(req, []*http.Request{req})
	require.Error(t, err, "CheckRedirect must refuse redirects")
	assert.ErrorIs(t, err, ErrSSRFBlocked,
		"redirect refusal should wrap ErrSSRFBlocked")
}

// TestSSRFSafeClient_BlocksInternalDestinations verifies that requests to
// internal/special IP literals are rejected at dial time, before any
// connection is established (no egress). Each host is an IP literal so the
// resolve-and-validate hook classifies it directly with no DNS lookup.
func TestSSRFSafeClient_BlocksInternalDestinations(t *testing.T) {
	t.Parallel()

	client := NewSSRFSafeClient()

	// host is written as it appears in a URL authority (IPv6 bracketed).
	hosts := []struct {
		name string
		host string
	}{
		{"loopback v4", "127.0.0.1"},
		{"loopback v6", "[::1]"},
		{"link-local metadata", "169.254.169.254"},
		{"private 10/8", "10.0.0.1"},
		{"private 192.168/16", "192.168.0.1"},
		{"cgnat 100.64/10", "100.64.0.1"},
		{"benchmarking 198.18/15", "198.18.0.1"},
	}

	for _, tc := range hosts {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+tc.host+"/", nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err, "request to internal host %s must fail", tc.host)
			assert.ErrorIs(t, err, ErrSSRFBlocked,
				"dial-time block for %s should wrap ErrSSRFBlocked", tc.host)
		})
	}
}

// TestSSRFSafeClient_ClassifiesSpecialUseRanges verifies that isInternalOrSpecial
// treats RFC 6598 carrier-grade NAT (100.64.0.0/10) and RFC 2544 benchmarking
// (198.18.0.0/15) as internal, closing a gap left by netip's built-in predicates.
func TestSSRFSafeClient_ClassifiesSpecialUseRanges(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"100.64.0.1", "198.18.0.1"} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			assert.True(t, isInternalOrSpecial(netip.MustParseAddr(raw)),
				"%s should be classified internal/special", raw)
		})
	}
}

// TestSSRFSafeClient_RejectsPlainHTTP verifies the HTTPS-only enforcement.
// The scheme check happens in the transport before any dial, so using an
// internal literal host guarantees no egress regardless of the outcome.
func TestSSRFSafeClient_RejectsPlainHTTP(t *testing.T) {
	t.Parallel()

	client := NewSSRFSafeClient()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.0.0.1/", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "plain-http request must be rejected")
	assert.ErrorIs(t, err, ErrSSRFBlocked,
		"https-only rejection should wrap ErrSSRFBlocked")
}
