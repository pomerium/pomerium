package registry_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pomerium/pomerium/internal/registry"
	pb "github.com/pomerium/pomerium/pkg/grpc/registry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

func TestRegistry(t *testing.T) {
	l := bufconn.Listen(1024)
	defer l.Close()

	dialer := func(context.Context, string) (net.Conn, error) {
		return l.Dial()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gs := grpc.NewServer()

	ttl := time.Second
	pb.RegisterRegistryServer(gs, registry.NewInMemoryServer(ctx, ttl))

	go func() {
		err := gs.Serve(l)
		assert.NoError(t, err)
	}()

	conn, err := grpc.DialContext(ctx, "inmem", grpc.WithContextDialer(dialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := pb.NewRegistryClient(conn)

	registerTC := []struct {
		svc         []*pb.Service
		expectError bool
	}{
		{[]*pb.Service{{Kind: pb.ServiceKind_DATABROKER, Endpoint: "http://localhost"}}, false},
	}

	cmpOpts := cmpopts.IgnoreUnexported(pb.Service{})

	for i, tc := range registerTC {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			kinds := []pb.ServiceKind{pb.ServiceKind_DATABROKER}
			wc, err := client.Watch(ctx, &pb.ListRequest{Kinds: kinds})
			require.NoError(t, err)

			entries, err := wc.Recv()
			require.NoError(t, err)
			assert.Empty(t, entries.Services)

			reportResp, err := client.Report(ctx, &pb.RegisterRequest{Services: tc.svc})
			if tc.expectError {
				assert.Error(t, err, "%v", tc)
				return
			}
			assert.NoError(t, err, "%v", tc)
			assert.LessOrEqual(t, reportResp.CallBackAfter.AsDuration(), ttl)

			entries, err = client.List(ctx, &pb.ListRequest{Kinds: kinds})
			require.NoError(t, err)
			diff := cmp.Diff(tc.svc, entries.Services, cmpOpts)
			assert.Empty(t, diff)

			entries, err = wc.Recv()
			assert.NoError(t, err)
			diff = cmp.Diff(tc.svc, entries.Services, cmpOpts)
			assert.Empty(t, diff)

			entries, err = wc.Recv()
			assert.NoError(t, err)
			assert.Empty(t, entries.Services)

			entries, err = client.List(ctx, &pb.ListRequest{Kinds: kinds})
			require.NoError(t, err)
			assert.Empty(t, entries.Services)
		})
	}
}
