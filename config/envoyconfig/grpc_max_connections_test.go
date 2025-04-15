package envoyconfig_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	"google.golang.org/grpc/interop/grpc_testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func TestMaxGRPCConn(t *testing.T) {
	const maxConnections = 1025

	env := testenv.New(t)
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.RuntimeFlags[config.RuntimeFlagTmpUnlimitedConnections] = true
	}))

	up := upstreams.GRPC(insecure.NewCredentials())
	srv := interop.NewTestServer()
	grpc_testing.RegisterTestServiceServer(up, srv)

	h2c := up.Route().
		From(env.SubdomainURL("grpc-h2c")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	grpcTestRunner := func(ctx context.Context) error {
		cc := up.Dial(h2c)

		client := grpc_testing.NewTestServiceClient(cc)
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
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}

		return nil
	}

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	ctx, cancel := context.WithCancel(env.Context())
	t.Cleanup(cancel)
	ch := make(chan error)
	for range maxConnections {
		go func() {
			if err := grpcTestRunner(ctx); err != nil {
				ch <- err
				return
			}

			ch <- nil
			<-ctx.Done()
		}()
	}

	for i := range maxConnections {
		select {
		case err := <-ch:
			t.Logf("#%d: got response %v", i, err)

			if !assert.NoError(t, err) {
				cancel()
				t.FailNow()
			}
		case <-ctx.Done():
			t.Fatal("timeout")
		}
	}

	cancel()
}
