package controlplane

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
)

func Test_getAllRouteableDomains(t *testing.T) {
	options := &config.Options{
		Addr:            "127.0.0.1:9000",
		GRPCAddr:        "127.0.0.1:9001",
		Services:        "all",
		AuthenticateURL: mustParseURL("https://authenticate.example.com"),
		AuthorizeURL:    mustParseURL("https://authorize.example.com:9001"),
		CacheURL:        mustParseURL("https://cache.example.com:9001"),
		Policies: []config.Policy{
			{Source: &config.StringURL{URL: mustParseURL("https://a.example.com")}},
			{Source: &config.StringURL{URL: mustParseURL("https://b.example.com")}},
			{Source: &config.StringURL{URL: mustParseURL("https://c.example.com")}},
		},
	}
	t.Run("http", func(t *testing.T) {
		actual := getAllRouteableDomains(options, "127.0.0.1:9000")
		expect := []string{
			"a.example.com",
			"authenticate.example.com",
			"b.example.com",
			"c.example.com",
		}
		assert.Equal(t, expect, actual)
	})
	t.Run("grpc", func(t *testing.T) {
		actual := getAllRouteableDomains(options, "127.0.0.1:9001")
		expect := []string{
			"authorize.example.com:9001",
			"cache.example.com:9001",
		}
		assert.Equal(t, expect, actual)
	})
}
