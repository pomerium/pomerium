package registry_test

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/registry"
	pb "github.com/pomerium/pomerium/pkg/grpc/registry"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

	go gs.Serve(l)
	defer gs.Stop()

	conn, err := grpc.DialContext(ctx, "inmem", grpc.WithContextDialer(dialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	client := pb.NewRegistryClient(conn)

	brSvc := &pb.Service{Kind: pb.ServiceKind_DATABROKER, Endpoint: "http://localhost"}
	authSvc := &pb.Service{Kind: pb.ServiceKind_AUTHORIZE, Endpoint: "http://localhost"}
	mtrcsSvc := &pb.Service{Kind: pb.ServiceKind_PROMETHEUS_METRICS, Endpoint: "http://localhost/metrics"}

	t.Run("expiration", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		kinds := []pb.ServiceKind{pb.ServiceKind_DATABROKER}
		svc := []*pb.Service{brSvc}

		wc, err := client.Watch(ctx, &pb.ListRequest{Kinds: kinds})
		require.NoError(t, err)

		entries, err := wc.Recv()
		require.NoError(t, err)
		assert.Empty(t, entries.Services)

		reportResp, err := client.Report(ctx, &pb.RegisterRequest{Services: svc})
		require.NoError(t, err)
		assert.LessOrEqual(t, reportResp.CallBackAfter.AsDuration(), ttl)

		entries, err = client.List(ctx, &pb.ListRequest{Kinds: kinds})
		require.NoError(t, err)
		assertEqual(t, svc, entries.Services)

		entries, err = wc.Recv()
		assert.NoError(t, err)
		assertEqual(t, svc, entries.Services)

		// wait to expire - an empty list should arrive
		entries, err = wc.Recv()
		assert.NoError(t, err)
		assert.Empty(t, entries.Services)

		entries, err = client.List(ctx, &pb.ListRequest{Kinds: kinds})
		require.NoError(t, err)
		assert.Empty(t, entries.Services)
	})
	t.Run("filters", func(t *testing.T) {
		reportResp, err := client.Report(ctx, &pb.RegisterRequest{Services: []*pb.Service{brSvc, authSvc, mtrcsSvc}})
		assert.NoError(t, err, "%v")
		assert.LessOrEqual(t, reportResp.CallBackAfter.AsDuration(), ttl)

		entries, err := client.List(ctx, &pb.ListRequest{Kinds: []pb.ServiceKind{pb.ServiceKind_DATABROKER}})
		require.NoError(t, err)
		assertEqual(t, []*pb.Service{brSvc}, entries.Services)

		entries, err = client.List(ctx, &pb.ListRequest{Kinds: []pb.ServiceKind{pb.ServiceKind_DATABROKER, pb.ServiceKind_PROMETHEUS_METRICS}})
		require.NoError(t, err)
		assertEqual(t, []*pb.Service{brSvc, mtrcsSvc}, entries.Services)

		entries, err = client.List(ctx, &pb.ListRequest{Kinds: []pb.ServiceKind{}}) // nil filter means all
		require.NoError(t, err)
		assertEqual(t, []*pb.Service{brSvc, mtrcsSvc, authSvc}, entries.Services)
	})
}

type serviceList []*pb.Service

func (l serviceList) Len() int           { return len(l) }
func (l serviceList) Less(i, j int) bool { return l[i].Kind < l[j].Kind }
func (l serviceList) Swap(i, j int)      { t := l[i]; l[i] = l[j]; l[j] = t }

func assertEqual(t *testing.T, want, got []*pb.Service) {
	t.Helper()

	sort.Sort(serviceList(want))
	sort.Sort(serviceList(got))

	diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(pb.Service{}))
	if diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
}
