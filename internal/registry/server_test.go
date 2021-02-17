package registry_test

import (
	"context"
	"fmt"
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

const (
	ttl = time.Second
)

func TestRegistryExpiration(t *testing.T) {
	t.Parallel()

	brSvc := &pb.Service{Kind: pb.ServiceKind_DATABROKER, Endpoint: "http://localhost"}
	kinds := []pb.ServiceKind{pb.ServiceKind_DATABROKER}
	svc := []*pb.Service{brSvc}

	ctx, client, cancel, err := newTestRegistry()
	require.NoError(t, err)
	defer cancel()

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
}

func TestRegistryFilter(t *testing.T) {
	t.Parallel()

	ctx, client, cancel, err := newTestRegistry()
	require.NoError(t, err)
	defer cancel()

	brSvc := &pb.Service{Kind: pb.ServiceKind_DATABROKER, Endpoint: "http://localhost"}
	authSvc := &pb.Service{Kind: pb.ServiceKind_AUTHENTICATE, Endpoint: "http://localhost"}
	mtrcsSvc := &pb.Service{Kind: pb.ServiceKind_PROMETHEUS_METRICS, Endpoint: "http://localhost/metrics"}

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
}
func TestRegistryReplacement(t *testing.T) {
	t.Parallel()

	svcA := &pb.Service{Kind: pb.ServiceKind_PROMETHEUS_METRICS, Endpoint: "http://host-a/metrics"}
	svcB := &pb.Service{Kind: pb.ServiceKind_PROMETHEUS_METRICS, Endpoint: "http://host-b/metrics"}

	ctx, client, cancel, err := newTestRegistry()
	require.NoError(t, err)
	defer cancel()

	wc, err := client.Watch(ctx, &pb.ListRequest{Kinds: []pb.ServiceKind{pb.ServiceKind_PROMETHEUS_METRICS}})
	require.NoError(t, err)

	entries, err := wc.Recv()
	require.NoError(t, err)
	assert.Empty(t, entries.Services)

	reportResp, err := client.Report(ctx, &pb.RegisterRequest{Services: []*pb.Service{svcA}})
	require.NoError(t, err)

	entries, err = wc.Recv()
	assert.NoError(t, err)
	assertEqual(t, []*pb.Service{svcA}, entries.Services)

	time.Sleep(reportResp.CallBackAfter.AsDuration())

	reportResp, err = client.Report(ctx, &pb.RegisterRequest{Services: []*pb.Service{svcB}})
	require.NoError(t, err)

	// first, both services should be reported
	entries, err = wc.Recv()
	assert.NoError(t, err)
	assertEqual(t, []*pb.Service{svcA, svcB}, entries.Services)

	// then, svcA expires
	entries, err = wc.Recv()
	assert.NoError(t, err)
	assertEqual(t, []*pb.Service{svcB}, entries.Services)

	// finally, both expire
	entries, err = wc.Recv()
	assert.NoError(t, err)
	assert.Empty(t, entries.Services)
}

func TestRegistryErrors(t *testing.T) {
	t.Parallel()

	ctx, client, cancel, err := newTestRegistry()
	require.NoError(t, err)
	defer cancel()

	tc := [][]*pb.Service{
		{{Kind: pb.ServiceKind_UNDEFINED_DO_NOT_USE, Endpoint: "http://localhost"}},
		{{Kind: pb.ServiceKind_PROMETHEUS_METRICS, Endpoint: ""}},
		{{Kind: pb.ServiceKind_PROMETHEUS_METRICS, Endpoint: "/metrics"}},
		{},
		nil,
	}

	for _, svc := range tc {
		_, err := client.Report(ctx, &pb.RegisterRequest{Services: svc})
		assert.Error(t, err, svc)
	}
}

func newTestRegistry() (context.Context, pb.RegistryClient, func(), error) {
	cancel := new(cancelAll)

	l := bufconn.Listen(1024)
	cancel.Append(func() { l.Close() })

	dialer := func(context.Context, string) (net.Conn, error) {
		return l.Dial()
	}

	ctx, ctxCancel := context.WithCancel(context.Background())
	cancel.Append(ctxCancel)

	gs := grpc.NewServer()

	ttl := time.Second
	pb.RegisterRegistryServer(gs, registry.NewInMemoryServer(ctx, ttl))

	go gs.Serve(l)
	cancel.Append(gs.Stop)

	conn, err := grpc.DialContext(ctx, "inmem", grpc.WithContextDialer(dialer), grpc.WithInsecure())
	if err != nil {
		cancel.Cancel()
		return nil, nil, nil, fmt.Errorf("failed to dial bufnet: %w", err)
	}
	cancel.Append(func() { conn.Close() })

	return ctx, pb.NewRegistryClient(conn), cancel.Cancel, nil
}

type cancelAll []func()

func (c *cancelAll) Append(fn func()) { *c = append(*c, fn) }
func (c *cancelAll) Cancel() {
	for _, fn := range *c {
		fn()
	}
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
