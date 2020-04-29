//go:generate protoc -I ../internal/grpc/authorize/ --go_out=plugins=grpc:../internal/grpc/authorize/ ../internal/grpc/authorize/authorize.proto

package authorize

import (
	"context"
	"net/url"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/log"
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
		URL:        getFullURL(in.GetRequestUrl(), in.GetRequestHost()),
	}
	reply, err := a.pe.IsAuthorized(ctx, req)
	log.Info().
		// request
		Str("method", req.Method).
		Str("url", req.URL).
		// reply
		Bool("allow", reply.Allow).
		Strs("deny-reasons", reply.DenyReasons).
		Str("user", reply.User).
		Str("email", reply.Email).
		Strs("groups", reply.Groups).
		Msg("authorize.grpc.IsAuthorized")
	return reply, err
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

func getFullURL(rawurl, host string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		u = &url.URL{Path: rawurl}
	}
	if u.Host == "" {
		u.Host = host
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	return u.String()
}
