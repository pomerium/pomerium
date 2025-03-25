// Package authenticateflow implements the core authentication flow. This
// includes creating and parsing sign-in redirect URLs, storing and retrieving
// session data, and handling authentication callback URLs.
package authenticateflow

import (
	"context"
	"fmt"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

func populateUserFromClaims(u *user.User, claims map[string]any) {
	if v, ok := claims["name"]; ok {
		u.Name = fmt.Sprint(v)
	}
	if v, ok := claims["email"]; ok {
		u.Email = fmt.Sprint(v)
	}
	if u.Claims == nil {
		u.Claims = make(map[string]*structpb.ListValue)
	}
	for k, vs := range identity.Claims(claims).Flatten().ToPB() {
		u.Claims[k] = vs
	}
}

var outboundDatabrokerTraceClientOpts = []trace.ClientStatsHandlerOption{
	trace.WithStatsInterceptor(ignoreNotFoundErrors),
}

func ignoreNotFoundErrors(ctx context.Context, rs stats.RPCStats) stats.RPCStats {
	if end, ok := rs.(*stats.End); ok && end.IsClient() {
		if status.Code(end.Error) == codes.NotFound {
			oteltrace.SpanFromContext(ctx).AddEvent("status code: NotFound")
			return &stats.End{
				Client:    end.Client,
				BeginTime: end.BeginTime,
				EndTime:   end.EndTime,
				Trailer:   end.Trailer,
				Error:     nil,
			}
		}
	}
	return rs
}
