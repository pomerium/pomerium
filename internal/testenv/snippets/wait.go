package snippets

import (
	"context"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func WaitStartupComplete(t testing.TB, env testenv.Environment, timeout ...time.Duration) time.Duration {
	start := time.Now()
	recorder := env.NewLogRecorder()
	if len(timeout) == 0 {
		timeout = append(timeout, 1*time.Minute)
	}
	ctx, ca := context.WithTimeout(env.Context(), timeout[0])
	defer ca()
	recorder.WaitForMatch(map[string]any{
		"syncer_id":   "databroker",
		"syncer_type": "type.googleapis.com/pomerium.config.Config",
		"message":     "listening for updates",
	}, timeout...)
	cc, err := grpc.Dial(env.DatabrokerURL().Value(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(grpcutil.WithUnarySignedJWT(env.SharedSecret)),
		grpc.WithChainStreamInterceptor(grpcutil.WithStreamSignedJWT(env.SharedSecret)),
	)
	env.Require().NoError(err)
	env.Require().True(cc.WaitForStateChange(ctx, connectivity.Ready))
	return time.Since(start)
}
