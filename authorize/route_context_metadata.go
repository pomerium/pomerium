package authorize

import (
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/authorize/evaluator"
)

// RouteContextMetadataNamespace is the namespace for route context metadata
// that is set by ext_authz and read by ext_proc.
const RouteContextMetadataNamespace = "com.pomerium.route-context"

// BuildRouteContextMetadata creates the dynamic metadata struct that will be
// passed from ext_authz to ext_proc for MCP routes. This metadata contains
// route and session information needed for response interception.
func BuildRouteContextMetadata(request *evaluator.Request) *structpb.Struct {
	if request == nil || request.Policy == nil {
		return nil
	}

	// Only set metadata for MCP server routes
	if !request.Policy.IsMCPServer() {
		return nil
	}

	fields := map[string]*structpb.Value{
		"route_id": structpb.NewStringValue(request.EnvoyRouteID),
		"is_mcp":   structpb.NewBoolValue(true),
	}

	// Add session information if available
	if request.Session.ID != "" {
		fields["session_id"] = structpb.NewStringValue(request.Session.ID)
	}

	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			RouteContextMetadataNamespace: {
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: fields,
					},
				},
			},
		},
	}
}
