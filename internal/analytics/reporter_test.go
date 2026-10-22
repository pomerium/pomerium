package analytics_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/analytics"
)

func TestCreatePosthogEvent(t *testing.T) {
	t.Parallel()

	options := config.NewDefaultOptions()
	options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
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

	evt := analytics.New(analytics.WithMaxDomains(5)).CreatePosthogEvent(t.Context(), cfg, 10, 20)
	assert.Equal(t, "c903eaea12a1cdce23857f76c7525218ad36e190eb93a21d93c2ed1a0a81aae7", evt.DistinctId)
	assert.Equal(t, "core_periodic_analytics", evt.Event)
	assert.Equal(t, []string{
		"a.b.route-00.com",
		"a.b.route-01.com",
		"a.b.route-02.com",
		"a.b.route-03.com",
		"a.b.route-04.com",
	}, evt.Properties["domains"])
	assert.Equal(t, 600, evt.Properties["route_count"])
	assert.Equal(t, 100, evt.Properties["kubernetes_route_count"])
	assert.Equal(t, 100, evt.Properties["mcp_route_count"])
	assert.Equal(t, 100, evt.Properties["ssh_route_count"])
	assert.Equal(t, 100, evt.Properties["tcp_route_count"])
	assert.Equal(t, 100, evt.Properties["udp_route_count"])
}
