package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/integration/flows"
)

func BenchmarkLoggedInUserAccess(b *testing.B) {
	ctx := b.Context()
	client := getClient(b, false)
	res, err := flows.Authenticate(ctx, client, mustParseURL("https://httpdetails.localhost.pomerium.io/by-domain"),
		flows.WithEmail("user1@dogs.test"))
	require.NoError(b, err)
	_ = res.Body.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpdetails.localhost.pomerium.io/by-domain", nil)
		require.NoError(b, err)
		res, err := client.Do(req)
		require.NoError(b, err)
		res.Body.Close()
	}
}

func BenchmarkLoggedOutUserAccess(b *testing.B) {
	ctx := b.Context()
	client := getClient(b, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpdetails.localhost.pomerium.io/by-domain", nil)
		require.NoError(b, err)
		res, err := client.Do(req)
		require.NoError(b, err)
		res.Body.Close()
	}
}
