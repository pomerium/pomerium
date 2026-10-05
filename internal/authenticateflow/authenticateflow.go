// Package authenticateflow implements the core authentication flow. This
// includes creating and parsing sign-in redirect URLs, storing and retrieving
// session data, and handling authentication callback URLs.
package authenticateflow

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/google/uuid"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

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

type SignOutHints struct {
	IDTokenHint string
	LogoutHint  string
}

func idpSessionID(browserID, userID string) string {
	var idpSessID string
	if browserID != "" {
		hasher := xxhash.New()
		_, _ = hasher.Write([]byte(browserID))
		_, _ = hasher.Write([]byte(userID))
		idBytes := hasher.Sum(nil)
		idpSessID = hex.EncodeToString(idBytes)

	} else {
		idpSessID = uuid.New().String()
	}
	return idpSessID
}
