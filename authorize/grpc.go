//go:generate protoc -I ../internal/grpc/authorize/ --go_out=plugins=grpc:../internal/grpc/authorize/ ../internal/grpc/authorize/authorize.proto

package authorize // import "github.com/pomerium/pomerium/authorize"
import (
	"context"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

// IsAuthorized checks to see if a given user is authorized to make a request.
func (a *Authorize) IsAuthorized(ctx context.Context, in *authorize.IsAuthorizedRequest) (*authorize.IsAuthorizedReply, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.grpc.IsAuthorized")
	defer span.End()

	req := &evaluator.Request{
		User:       in.GetUserToken(),
		Header:     cloneHeaders(in.GetRequestHeaders()),
		Host:       in.GetRequestHost(),
		Method:     in.GetRequestMethod(),
		RequestURI: in.GetRequestRequestUri(),
		RemoteAddr: in.GetRequestRemoteAddr(),
		URL:        in.GetRequestUrl(),
	}
	return a.pe.IsAuthorized(ctx, req)
}

type protoHeader map[string]*authorize.IsAuthorizedRequest_Headers

func cloneHeaders(in protoHeader) map[string][]string {
	out := make(map[string][]string, len(in))
	for key, values := range in {
		newValues := make([]string, len(values.Value))
		copy(newValues, values.Value)
		out[key] = newValues
	}
	return out
}
