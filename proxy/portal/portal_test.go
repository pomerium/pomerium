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

	assert.Equal(t, []portal.Route{
		{
			ID:          "4e71df99c0317efb",
			Name:        "from",
			Type:        "http",
			From:        "https://from.example.com",
			Description: "ROUTE #1",
			LogoURL:     "https://logo.example.com",
		},
		{
			ID:   "7c377f11cdb9700e",
			Name: "from-path",
			Type: "http",
			From: "https://from.example.com",
		},
		{
			ID:             "708e3cbd0bbe8547",
			Name:           "postgres",
			Type:           "tcp",
			From:           "tcp+https://postgres.example.com:5432",
			ConnectCommand: "pomerium-cli tcp postgres.example.com:5432",
		},
		{
			ID:             "2dd08d87486e051a",
			Name:           "dns",
			Type:           "udp",
			From:           "udp+https://dns.example.com:53",
			ConnectCommand: "pomerium-cli udp dns.example.com:53",
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
	}))
}
