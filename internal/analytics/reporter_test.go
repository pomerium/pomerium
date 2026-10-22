package analytics_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/analytics"
)

func TestGetProperties(t *testing.T) {
	t.Parallel()

	options := config.NewDefaultOptions()
	for i := range 100 {
		options.Routes = append(options.Routes,
			config.Policy{
				From: fmt.Sprintf("https://a.b.c.d.route-%02d.com", i),
			},
			config.Policy{
				From: fmt.Sprintf("https://a.b.c.route-%02d.com", i),
				MCP:  &config.MCP{Server: &config.MCPServer{}},
			},
			config.Policy{
				From: fmt.Sprintf("ssh://a.b.c.route-%02d.com", i),
			},
			config.Policy{
				From: fmt.Sprintf("tcp+https://a.b.c.route-%02d.com:9000", i),
			},
			config.Policy{
				From: fmt.Sprintf("udp+https://a.b.c.route-%02d.com:9000", i),
			},
			config.Policy{
				From:                          fmt.Sprintf("https://a.b.route-%02d.com", i),
				KubernetesServiceAccountToken: "TOKEN",
			})
	}
	cfg := config.New(options)

	p := analytics.New(analytics.WithMaxDomains(5)).GetProperties(t.Context(), cfg, 10, 20)
	assert.Equal(t, []string{
		"a.b.route-00.com",
		"a.b.route-01.com",
		"a.b.route-02.com",
		"a.b.route-03.com",
		"a.b.route-04.com",
	}, p["domains"])
	assert.Equal(t, 600, p["route_count"])
	assert.Equal(t, 100, p["kubernetes_route_count"])
	assert.Equal(t, 100, p["mcp_route_count"])
	assert.Equal(t, 100, p["ssh_route_count"])
	assert.Equal(t, 100, p["tcp_route_count"])
	assert.Equal(t, 100, p["udp_route_count"])
}
