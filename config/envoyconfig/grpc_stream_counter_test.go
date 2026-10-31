package envoyconfig_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop"
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/stats"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

type streamCounter struct {
	mu      sync.Mutex
	current map[string]int
	max     map[string]int
}

type connKey struct{}

func newStreamCounter() *streamCounter {
	return &streamCounter{
		current: make(map[string]int),
		max:     make(map[string]int),
	}
}

func (s *streamCounter) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	id := info.RemoteAddr.String() + "->" + info.LocalAddr.String()
	return context.WithValue(ctx, connKey{}, id)
}

func (s *streamCounter) HandleConn(context.Context, stats.ConnStats) {}

func (s *streamCounter) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

func (s *streamCounter) HandleRPC(ctx context.Context, rs stats.RPCStats) {
	id, ok := ctx.Value(connKey{}).(string)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch rs.(type) {
	case *stats.Begin:
		s.current[id]++
		if s.current[id] > s.max[id] {
			s.max[id] = s.current[id]
		}
	case *stats.End:
		s.current[id]--
	}
}

func (s *streamCounter) Max() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := 0
	for _, v := range s.max {
		if v > m {
			m = v
		}
	}
	return m
}

func TestMaxGRPCStreamsPerConnection(t *testing.T) {
	const maxStreams = 100
	const totalRequests = maxStreams * 5

	env := testenv.New(t)

	counter := newStreamCounter()
	up := upstreams.GRPC(insecure.NewCredentials(),
		upstreams.ServerOpts(grpc.StatsHandler(counter)))
	srv := interop.NewTestServer()
	grpc_testing.RegisterTestServiceServer(up, srv)

	route := up.Route().
		From(env.SubdomainURL("grpc-streams")).
		Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	target := strings.TrimPrefix(route.URL().Value(), "https://")
	cc, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(env.ServerCAs(), "")),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	require.NoError(t, err)
	defer cc.Close()

	client := grpc_testing.NewTestServiceClient(cc)
	ctx, cancel := context.WithCancel(env.Context())
	t.Cleanup(cancel)

	ch := make(chan error, totalRequests)
	for i := 0; i < totalRequests; i++ {
		go func() {
			call, err := client.FullDuplexCall(ctx)
			if err != nil {
				ch <- fmt.Errorf("call: %w", err)
				return
			}
			err = call.Send(&grpc_testing.StreamingOutputCallRequest{
				ResponseParameters: []*grpc_testing.ResponseParameters{{Size: 1}},
			})
			if err != nil {
				ch <- fmt.Errorf("send: %w", err)
				return
			}
			if _, err = call.Recv(); err != nil {
				ch <- fmt.Errorf("recv: %w", err)
				return
			}
			ch <- nil
			<-ctx.Done()
			_ = call.CloseSend()
		}()
	}

	for i := 0; i < totalRequests; i++ {
		select {
		case err := <-ch:
			if !assert.NoError(t, err) {
				cancel()
				t.FailNow()
			}
		case <-ctx.Done():
			t.Fatal("timeout")
		}
	}

	cancel()

	assert.Equal(t, maxStreams, counter.Max())
}
