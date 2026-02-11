package authorize

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
)

func TestBuildRouteContextMetadata(t *testing.T) {
	t.Parallel()

	mcpPolicy := &config.Policy{
		MCP: &config.MCP{Server: &config.MCPServer{}},
	}
	nonMCPPolicy := &config.Policy{}

	t.Run("nil request returns nil", func(t *testing.T) {
		result := BuildRouteContextMetadata(nil)
		assert.Nil(t, result)
	})

	t.Run("nil policy returns nil", func(t *testing.T) {
		result := BuildRouteContextMetadata(&evaluator.Request{})
		assert.Nil(t, result)
	})

	t.Run("non-MCP policy returns nil", func(t *testing.T) {
		result := BuildRouteContextMetadata(&evaluator.Request{
			Policy: nonMCPPolicy,
		})
		assert.Nil(t, result)
	})

	t.Run("empty EnvoyRouteID returns nil", func(t *testing.T) {
		result := BuildRouteContextMetadata(&evaluator.Request{
			Policy:       mcpPolicy,
			EnvoyRouteID: "",
		})
		assert.Nil(t, result)
	})

	t.Run("MCP policy with session ID", func(t *testing.T) {
		result := BuildRouteContextMetadata(&evaluator.Request{
			Policy:       mcpPolicy,
			EnvoyRouteID: "route-123",
			Session:      evaluator.RequestSession{ID: "session-456"},
		})

		require.NotNil(t, result)

		// Verify outer struct has the route context namespace key
		outerFields := result.GetFields()
		require.Contains(t, outerFields, extproc.RouteContextMetadataNamespace)

		// Verify inner struct fields
		inner := outerFields[extproc.RouteContextMetadataNamespace].GetStructValue()
		require.NotNil(t, inner)
		innerFields := inner.GetFields()

		assert.Equal(t, "route-123", innerFields[extproc.FieldRouteID].GetStringValue())
		assert.Equal(t, "session-456", innerFields[extproc.FieldSessionID].GetStringValue())
		assert.True(t, innerFields[extproc.FieldIsMCP].GetBoolValue())
	})

	t.Run("MCP policy without session ID", func(t *testing.T) {
		result := BuildRouteContextMetadata(&evaluator.Request{
			Policy:       mcpPolicy,
			EnvoyRouteID: "route-789",
		})

		require.NotNil(t, result)

		inner := result.GetFields()[extproc.RouteContextMetadataNamespace].GetStructValue()
		require.NotNil(t, inner)
		innerFields := inner.GetFields()

		assert.Equal(t, "route-789", innerFields[extproc.FieldRouteID].GetStringValue())
		assert.True(t, innerFields[extproc.FieldIsMCP].GetBoolValue())
		assert.NotContains(t, innerFields, extproc.FieldSessionID)
	})
}
