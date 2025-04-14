package envoyconfig_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	"google.golang.org/grpc/interop/grpc_testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func TestMaxGRPCConn(t *testing.T) {
	env := testenv.New(t)

	up := upstreams.GRPC(insecure.NewCredentials())
	srv := interop.NewTestServer()
	grpc_testing.RegisterTestServiceServer(up, srv)

	h2c := up.Route().
		From(env.SubdomainURL("grpc-h2c")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	const maxConnections = 1025

	ctx, cancel := context.WithCancel(env.Context())
	t.Cleanup(cancel)
	ch := make(chan error)
	tracer := env.Tracer()
	for i := range maxConnections {
		go func() {
			ctx, span := tracer.Start(ctx, "Test", oteltrace.WithAttributes(
				attribute.Float64("runner", float64(i)),
			))
			defer span.End()

			runner := newTestRunner(tracer)
			if err := runner.Connect(ctx, up, h2c); err != nil {
				span.SetStatus(codes.Error, "connect error")
				ch <- fmt.Errorf("connect: %w", err)
				return
			}

			if err := runner.Run(); err != nil {
				ch <- fmt.Errorf("run: %w", err)
				return
			}

			ch <- nil
			<-ctx.Done()
			span.SetStatus(codes.Ok, "context cancelled")
		}()
	}

	for i := 0; i < maxConnections; i++ {
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

type testRunner struct {
	tracer oteltrace.Tracer
	client grpc_testing.TestServiceClient
	call   grpc.BidiStreamingClient[grpc_testing.StreamingOutputCallRequest, grpc_testing.StreamingOutputCallResponse]
}

func newTestRunner(tracer oteltrace.Tracer) *testRunner {
	return &testRunner{
		tracer: tracer,
	}
}

func (r *testRunner) Connect(
	ctx context.Context,
	up upstreams.GRPCUpstream,
	h2c testenv.Route,
) error {
	cc := up.Dial(h2c)

	client := grpc_testing.NewTestServiceClient(cc)
	call, err := client.FullDuplexCall(ctx)
	if err != nil {
		return fmt.Errorf("call: %w", err)
	}
	r.call = call
	return nil
}

func (r *testRunner) Run() error {
	if err := r.Send(); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	if err := r.Recv(); err != nil {
		return fmt.Errorf("recv: %w", err)
	}

	return nil
}

func (r *testRunner) Send() error {
	return r.call.Send(&grpc_testing.StreamingOutputCallRequest{
		ResponseParameters: []*grpc_testing.ResponseParameters{
			{
				Size: 17,
			},
		},
		ResponseStatus: &grpc_testing.EchoStatus{
			Message: "hello",
		},
	})
}

func (r *testRunner) Recv() error {
	resp, err := r.call.Recv()
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}
	if n := len(resp.Payload.Body); n != 17 {
		return fmt.Errorf("got %d bytes, want 17", n)
	}

	return nil
}
