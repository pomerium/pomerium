package analytics_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/analytics"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func TestCreatePosthogEvent(t *testing.T) {
	t.Parallel()

	options := config.NewDefaultOptions()
	options.InstallationID = "INSTALLATION_ID"
	options.LicenseType = nullable.From(configpb.LicenseType_LICENSE_TYPE_COMMERCIAL)
	options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	for i := range 100 {
		options.Routes = append(options.Routes,
			config.Policy{
				AllowPublicUnauthenticatedAccess: true,
				From:                             fmt.Sprintf("https://a.b.c.d.route-%02d.com", i),
				Policy:                           mustParsePPL(t, `{"allow": {"or": [{"authenticated_user": 1}]}}`),
			},
			config.Policy{
				AllowedUsers: []string{"u1", "u2", "u3"},
				From:         fmt.Sprintf("https://a.b.c.route-%02d.com", i),
				MCP:          &config.MCP{Server: &config.MCPServer{}},
				Policy:       mustParsePPL(t, `{"allow": {"and": [{"accept": 1}]}}`),
			},
			config.Policy{
				From: fmt.Sprintf("ssh://a.b.c.route-%02d.com", i),
			},
			config.Policy{
				From: fmt.Sprintf("tcp+https://a.b.c.route-%02d.com:9000", i),
			},
			config.Policy{
				From: fmt.Sprintf("udp+https://a.b.c.route-%02d.com:9000", i),
				SubPolicies: []config.SubPolicy{{
					ID:        "p1",
					SourcePPL: `{"allow": {"or": [{"domain": "example.com"}]}}`,
				}},
			},
			config.Policy{
				From:                          fmt.Sprintf("https://a.b.route-%02d.com", i),
				KubernetesServiceAccountToken: "TOKEN",
			})
	}
	cfg := config.New(options)

	evt := analytics.New().CreatePosthogEvent(t.Context(), cfg, 10, 20)
	assert.Equal(t, "INSTALLATION_ID", evt.DistinctId)
	assert.Equal(t, "core_periodic_analytics", evt.Event)
	assert.Contains(t, evt.Properties, "build_version")

	// policy properties
	assert.Contains(t, evt.Properties, "policy_count")

	t.Run("pseudonymous", func(t *testing.T) {
		t.Parallel()

		options := config.NewDefaultOptions()
		options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))
		options.LicenseType = nullable.From(configpb.LicenseType_LICENSE_TYPE_COMMUNITY)
		options.Routes = []config.Policy{
			{
				From:   "https://example.com",
				Policy: mustParsePPL(t, `{"allow": {"or": [{"authenticated_user": 1}]}}`),
			},
		}
		cfg := config.New(options)
		evt := analytics.New().CreatePosthogEvent(t.Context(), cfg, 0, 0)
		assert.Equal(t, "bdS/DkMVmpzBR865YlvhMXucXSO3tfcDFySXu0nAtIo=", evt.DistinctId)
		assert.NotContains(t, evt.Groups, "installation_id")
		assert.NotContains(t, evt.Properties, "identity_provider_url")
		assert.NotContains(t, evt.Properties, "pseudonymous_identity_provider_url")
	})
}

func mustParsePPL(t testing.TB, raw string) *config.PPLPolicy {
	ppl, err := parser.New().ParseJSON(strings.NewReader(raw))
	require.NoError(t, err)
	return &config.PPLPolicy{Policy: ppl}
}
