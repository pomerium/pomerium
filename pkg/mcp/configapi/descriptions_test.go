package configapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
)

// TestMCPConfigAPI_ToolSchemasCarryFieldDescriptions verifies that the
// JSON Schema served to MCP clients includes the leading-comment doc for
// every proto field that has one. Without this, the LLM sees only field
// names and types — losing the operator-facing intent encoded in
// config.proto. We probe a handful of well-known fields whose comments
// are unlikely to disappear; the lint in lint_test.go enforces that no
// proto field ships without a comment in the first place.
func TestMCPConfigAPI_ToolSchemasCarryFieldDescriptions(t *testing.T) {
	t.Parallel()

	session := connectMCP(t, newTestServer(t, configconnect.UnimplementedConfigServiceHandler{}))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)

	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}

	// create_route's input contains a "route" message; the Route message has
	// many documented fields. We assert that at least one of the documented
	// fields actually carries the description text through to the schema.
	createRoute := byName["create_route"]
	require.NotNil(t, createRoute, "create_route tool should be registered")

	schema, ok := createRoute.InputSchema.(map[string]any)
	require.True(t, ok, "input schema should be a map")
	props, _ := schema["properties"].(map[string]any)
	routeProp, _ := props["route"].(map[string]any)
	require.NotNil(t, routeProp, "input schema must expose 'route'")

	// The "route" property is a nested message; descriptions for the Route
	// message itself, and for its individual fields, should be present.
	assert.NotEmpty(t, routeProp["description"],
		"Route message description should appear on the 'route' input property")

	routeProps, _ := routeProp["properties"].(map[string]any)
	require.NotEmpty(t, routeProps, "Route property must expand its own properties")

	// Probe a few stable Route fields. Each must carry the leading-comment
	// text we know lives in config.proto.
	probes := map[string]string{
		// JSONName -> substring expected in the description.
		"from":        "externally accessible URL",
		"to":          "destination",
		"description": "human-readable description",
		"prefix":      "begins with the given prefix",
	}
	for jsonName, expected := range probes {
		field, ok := routeProps[jsonName].(map[string]any)
		if !assert.True(t, ok, "route.%s must be in input schema", jsonName) {
			continue
		}
		desc, _ := field["description"].(string)
		assert.Contains(t, desc, expected,
			"route.%s description must surface its proto comment; got %q", jsonName, desc)
	}
}
