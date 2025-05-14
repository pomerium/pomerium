package authorize_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	"google.golang.org/grpc/interop/grpc_testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/jwtutil"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/authenticateapi"
)

func TestIDPTokenRequests(t *testing.T) {
	const maxRequests = 1000

	var verifyRequestCount atomic.Uint32
	mux := http.NewServeMux()
	mux.HandleFunc("/.pomerium/verify-access-token", func(w http.ResponseWriter, _ *http.Request) {
		verifyRequestCount.Add(1)
		json.NewEncoder(w).Encode(&authenticateapi.VerifyTokenResponse{
			Valid:  true,
			Claims: jwtutil.Claims{"sub": "test-user"},
		})
	})
	authSrv := httptest.NewTLSServer(mux)
	t.Cleanup(authSrv.Close)

	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		fmt := config.BearerTokenFormatIDPAccessToken
		cfg.Options.BearerTokenFormat = &fmt
		cfg.Options.AuthenticateURLString = authSrv.URL
	}))

	up := upstreams.GRPC(insecure.NewCredentials())
	srv := interop.NewTestServer()
	grpc_testing.RegisterTestServiceServer(up, srv)

	h2c := up.Route().
		From(env.SubdomainURL("grpc-h2c")).
		Policy(func(p *config.Policy) {
			var ppl config.PPLPolicy
			err := ppl.UnmarshalJSON([]byte(`{
				"allow": {
					"and": [{
						"user": {"is": "test-user"}
					}]
				}
			}`))
			require.NoError(t, err)
			p.Policy = &ppl
		})

	done := make(chan struct{})

	grpcTestRunner := func(ctx context.Context, client grpc_testing.TestServiceClient) error {
		ctx, span := env.Tracer().Start(ctx, "grpcTestRunner")
		defer span.End()

		call, err := client.FullDuplexCall(ctx)
		if err != nil {
			return fmt.Errorf("call: %w", err)
		}
		err = call.Send(&grpc_testing.StreamingOutputCallRequest{
			ResponseParameters: []*grpc_testing.ResponseParameters{
				{
					Size: 17,
				},
			},
			ResponseStatus: &grpc_testing.EchoStatus{
				Message: "hello",
			},
		})
		if err != nil {
			return fmt.Errorf("send: %w", err)
		}

		resp, err := call.Recv()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if n := len(resp.Payload.Body); n != 17 {
			return fmt.Errorf("got %d bytes, want 17", n)
		}

		go func() {
			<-done
			call.CloseSend()
			call.Recv()
		}()

		return nil
	}

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	cc := up.Dial(h2c, grpc.WithPerRPCCredentials(grpcBearerToken{"test-access-token"}))
	client := grpc_testing.NewTestServiceClient(cc)

	ctx, cancel := context.WithCancel(env.Context())
	t.Cleanup(cancel)
	ch := make(chan error)
	for i := range maxRequests {
		go func() {
			if err := grpcTestRunner(ctx, client); err != nil {
				ch <- fmt.Errorf("#%d: got error %w", i, err)
				return
			}

			ch <- nil
			<-ctx.Done()
		}()
	}

	var failed int
	for range maxRequests {
		select {
		case err := <-ch:
			if !assert.NoError(t, err) {
				failed++
			}
		case <-ctx.Done():
			t.Fatal("timeout")
		}
	}

	assert.Equal(t, verifyRequestCount.Load(), uint32(1))

	close(done)

	if failed > 0 {
		t.Logf("\n\n\n *** %d / %d REQUESTS FAILED ***", failed, maxRequests)
	}
}

type grpcBearerToken struct {
	token string
}

func (t grpcBearerToken) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (t grpcBearerToken) RequireTransportSecurity() bool {
	return false
}
