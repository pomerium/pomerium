package authorize

import (
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
)

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

	if request.EnvoyRouteID == "" {
		log.Error().Msg("authorize: MCP route has empty EnvoyRouteID, skipping metadata")
		return nil
	}

	fields := map[string]*structpb.Value{
		extproc.FieldRouteID: structpb.NewStringValue(request.EnvoyRouteID),
		extproc.FieldIsMCP:   structpb.NewBoolValue(true),
	}

	// Add session information if available
	if request.Session.ID != "" {
		fields[extproc.FieldSessionID] = structpb.NewStringValue(request.Session.ID)
	}

	// Add the actual upstream host so ext_proc can use it for discovery.
	// ext_proc sees the downstream :authority, but Envoy rewrites it to the upstream
	// host after ext_proc processes request headers, so ext_proc needs the real
	// upstream host from the route config.
	if len(request.Policy.To) > 0 {
		fields[extproc.FieldUpstreamHost] = structpb.NewStringValue(request.Policy.To[0].URL.Hostname())
	}

	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			extproc.RouteContextMetadataNamespace: {
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: fields,
					},
				},
			},
		},
	}
}
