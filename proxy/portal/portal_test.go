package portal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/proxy/portal"
)

func TestRouteFromConfigRoute(t *testing.T) {
	t.Parallel()

	to1, err := config.ParseWeightedUrls("https://to.example.com")
	require.NoError(t, err)
	to2, err := config.ParseWeightedUrls("tcp://postgres:5432")
	require.NoError(t, err)
	to3, err := config.ParseWeightedUrls("tcp://redis:6379")
	require.NoError(t, err)

	assert.Equal(t, []portal.Route{
		{
			ID:          "1013c6be524d7fbd",
			Name:        "from",
			Type:        "http",
			From:        "https://from.example.com",
			Description: "ROUTE #1",
			LogoURL:     "https://logo.example.com",
		},
		{
			ID:   "15fa6bb41b1f0bd2",
			Name: "from-path",
			Type: "http",
			From: "https://from.example.com",
		},
		{
			ID:             "773f5c76f710b230",
			Name:           "postgres",
			Type:           "tcp",
			From:           "tcp+https://postgres.example.com:5432",
			ConnectCommand: "pomerium-cli tcp postgres.example.com:5432",
		},
		{
			ID:             "74961d605a24b812",
			Name:           "dns",
			Type:           "udp",
			From:           "udp+https://dns.example.com:53",
			ConnectCommand: "pomerium-cli udp dns.example.com:53",
		},
		{
			ID:             "8544b096d71c5dfe",
			Name:           "redis",
			Type:           "tcp",
			From:           "tcp+https://proxy.corp.example.com:8443/redis.internal.example.com:6379",
			ConnectCommand: "pomerium-cli tcp tcp+https://proxy.corp.example.com:8443/redis.internal.example.com:6379",
		},
	}, portal.RoutesFromConfigRoutes([]*config.Policy{
		{
			From:        "https://from.example.com",
			To:          to1,
			Description: "ROUTE #1",
			LogoURL:     "https://logo.example.com",
		},
		{
			From: "https://from.example.com",
			To:   to1,
			Path: "/path",
		},
		{
			From: "tcp+https://postgres.example.com:5432",
			To:   to2,
		},
		{
			From: "udp+https://dns.example.com:53",
			To:   to2,
		},
		{
			Name: "redis",
			From: "tcp+https://proxy.corp.example.com:8443/redis.internal.example.com:6379",
			To:   to3,
		},
	}))
}
