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
	_, span := trace.StartSpan(ctx, "authorize.grpc.Authorize")
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
	ok, err := a.pe.IsAuthorized(ctx, req)
	if err != nil {
		return nil, err
	}
	return &authorize.IsAuthorizedReply{IsValid: ok}, nil
}

// IsAdmin checks to see if a given user has super user privleges.
func (a *Authorize) IsAdmin(ctx context.Context, in *authorize.IsAdminRequest) (*authorize.IsAdminReply, error) {
	_, span := trace.StartSpan(ctx, "authorize.grpc.IsAdmin")
	defer span.End()
	req := &evaluator.Request{
		User: in.GetUserToken(),
	}
	ok, err := a.pe.IsAdmin(ctx, req)
	if err != nil {
		return nil, err
	}
	return &authorize.IsAdminReply{IsValid: ok}, nil
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
