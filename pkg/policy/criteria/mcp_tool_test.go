package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestMCPTool(t *testing.T) {
	t.Parallel()

	t.Run("allow / exact tool name match", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        is: list_tables
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "tools/call", ToolCall: &InputMCPToolCall{Name: "list_tables"}}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonMCPToolMatch}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("disallowed / different tool name", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        is: list_tables
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "tools/call", ToolCall: &InputMCPToolCall{Name: "read_table"}}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPToolNoMatch}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("allow / tool name is in list", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        in: ["list_tables", "read_table"]
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "tools/call", ToolCall: &InputMCPToolCall{Name: "list_tables"}}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonMCPToolMatch}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("disallow / tool name not in list", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        in: ["list_tables", "read_table"]
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "tools/call", ToolCall: &InputMCPToolCall{Name: "delete_table"}}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPToolNoMatch}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("disallow / non-tools/call method", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        is: list_tables
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "some/other_method"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPNotAToolCall}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("disallow / no method name", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        is: list_tables
`, []*databroker.Record{}, Input{})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPNotAToolCall}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
	t.Run("deny / method name match", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  and:
    - mcp_tool:
        is: drop_table
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "tools/call", ToolCall: &InputMCPToolCall{Name: "drop_table"}}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonMCPToolMatch}, M{}}, res["deny"])
		require.Equal(t, A{false, A{}}, res["allow"])
	})
	t.Run("dont deny / non-tools/call method", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  and:
    - mcp_tool:
        is: drop_table
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "some/other_method"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPNotAToolCall}, M{}}, res["deny"])
		require.Equal(t, A{false, A{}}, res["allow"])
	})
	t.Run("deny=false: method is in a list of allowed methods", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  and:
    - mcp_tool:
        not_in: ["list_tables", "read_table"]
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "tools/call", ToolCall: &InputMCPToolCall{Name: "list_tables"}}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPToolNoMatch}, M{}}, res["deny"])
		require.Equal(t, A{false, A{}}, res["allow"])
	})
	t.Run("deny=true: method is in not in a list of allowed methods", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  and:
    - mcp_tool:
        not_in: ["list_tables", "read_table"]
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "tools/call", ToolCall: &InputMCPToolCall{Name: "drop_table"}}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonMCPToolMatch}, M{}}, res["deny"])
		require.Equal(t, A{false, A{}}, res["allow"])
	})
	t.Run("deny=false: not a tool call", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  and:
    - mcp_tool:
        in: ["drop_table", "update"]
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "initialize"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPNotAToolCall}, M{}}, res["deny"])
		require.Equal(t, A{false, A{}}, res["allow"])
	})
	t.Run("deny=false: not a tool call", func(t *testing.T) {
		res, err := evaluate(t, `
deny:
  and:
    - mcp_tool:
        not_in: ["query", "list_tables"]
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "initialize"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPNotAToolCall}, M{}}, res["deny"])
		require.Equal(t, A{false, A{}}, res["allow"])
	})
}
