package criteria

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestMCPTool(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        is: list_tables
`, []*databroker.Record{}, Input{MCP: InputMCP{Tool: "list_tables", Method: "tools/call"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonMCPToolOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("unauthorized", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        is: list_tables
`, []*databroker.Record{}, Input{MCP: InputMCP{Tool: "read_table", Method: "tools/call"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPToolUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("in list", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        in: ["list_tables", "read_table"]
`, []*databroker.Record{}, Input{MCP: InputMCP{Tool: "list_tables", Method: "tools/call"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonMCPToolOK}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("not in list", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        in: ["list_tables", "read_table"]
`, []*databroker.Record{}, Input{MCP: InputMCP{Tool: "delete_table", Method: "tools/call"}})
		require.NoError(t, err)
		require.Equal(t, A{false, A{ReasonMCPToolUnauthorized}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})

	t.Run("non-tools/call method should pass", func(t *testing.T) {
		res, err := evaluate(t, `
allow:
  and:
    - mcp_tool:
        is: list_tables
`, []*databroker.Record{}, Input{MCP: InputMCP{Method: "some/other_method"}})
		require.NoError(t, err)
		require.Equal(t, A{true, A{ReasonMCPNotAToolCall}, M{}}, res["allow"])
		require.Equal(t, A{false, A{}}, res["deny"])
	})
}
