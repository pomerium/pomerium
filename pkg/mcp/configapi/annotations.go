package configapi

import (
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// annotationsForMethod returns MCP tool annotations based on the RPC method name prefix.
// The naming convention in ConfigService is consistent:
//   - Get*, List* → read-only
//   - Create*     → additive (not destructive)
//   - Update*     → idempotent mutation (not destructive)
//   - Delete*     → destructive, idempotent
func annotationsForMethod(methodName string) *mcp.ToolAnnotations {
	f := false
	t := true
	openWorld := false

	switch {
	case strings.HasPrefix(methodName, "Get"), strings.HasPrefix(methodName, "List"):
		return &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: &openWorld,
		}
	case strings.HasPrefix(methodName, "Create"):
		return &mcp.ToolAnnotations{
			DestructiveHint: &f,
			OpenWorldHint:   &openWorld,
		}
	case strings.HasPrefix(methodName, "Update"):
		return &mcp.ToolAnnotations{
			DestructiveHint: &f,
			IdempotentHint:  true,
			OpenWorldHint:   &openWorld,
		}
	case strings.HasPrefix(methodName, "Delete"):
		return &mcp.ToolAnnotations{
			DestructiveHint: &t,
			IdempotentHint:  true,
			OpenWorldHint:   &openWorld,
		}
	default:
		return &mcp.ToolAnnotations{
			DestructiveHint: &t,
			OpenWorldHint:   &openWorld,
		}
	}
}
