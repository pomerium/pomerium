package databroker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"path"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// TestConfigSource_LeaderChangeKeepsRecords connects a ConfigSource to one
// node of a two node databroker cluster and moves the leader between the
// nodes. A leader change gives every syncer a new server version, so each one
// aborts and re-syncs its records. The config record never changes, so every
// config published during the re-syncs must still contain it.
//
// A config published while the config syncer has cleared its records but not
// yet delivered the re-synced ones is missing them. In a full Pomerium the
// other syncers' re-syncs rebuild the config at the same moment; here a
// background loop keeps rebuilding the config from the underlying source so
// that a rebuild reliably lands in that window, and the leader moves several
// times.
func TestConfigSource_LeaderChangeKeepsRecords(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	sharedKey := make([]byte, 32)
	_, _ = rand.Read(sharedKey)

	listenerA, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listenerB, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	nodeConfig := func(nodeID, leaderID string) *config.Config {
		o := config.NewDefaultOptions()
		o.SharedKey = base64.StdEncoding.EncodeToString(sharedKey)
		o.DataBroker.StorageType = "memory"
		o.DataBroker.ClusterNodeID = null.StringFrom(nodeID)
		o.DataBroker.ClusterLeaderID = null.StringFrom(leaderID)
		o.DataBroker.ClusterNodes = config.DataBrokerClusterNodes{
			{ID: "node-a", GRPCAddress: "http://" + listenerA.Addr().String()},
			{ID: "node-b", GRPCAddress: "http://" + listenerB.Addr().String()},
		}
		return config.New(o)
	}
	// record the sync calls the config source makes, to know when its
	// syncers have re-synced
	var callsMu sync.Mutex
	var calls []syncCall
	recordSyncCalls := grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		stream := &typeRecordingServerStream{ServerStream: ss}
		err := handler(srv, stream)
		callsMu.Lock()
		calls = append(calls, syncCall{method: path.Base(info.FullMethod), typeURL: stream.typeURL, code: status.Code(err)})
		callsMu.Unlock()
		return err
	})
	serve := func(li net.Listener, srv Server, opts ...grpc.ServerOption) {
		s := grpc.NewServer(opts...)
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
		go func() { _ = s.Serve(li) }()
		t.Cleanup(s.Stop)
		t.Cleanup(srv.Stop)
	}
	nodeA := NewClusteredServer(noop.NewTracerProvider(), NewBackendServer(noop.NewTracerProvider()), nodeConfig("node-a", "node-a"))
	serve(listenerA, nodeA, recordSyncCalls)
	nodeB := NewClusteredServer(noop.NewTracerProvider(), NewBackendServer(noop.NewTracerProvider()), nodeConfig("node-b", "node-a"))
	serve(listenerB, nodeB)

	// the config record carrying a route, as the ingress controller writes it
	data := protoutil.NewAny(&configpb.Config{
		Name: "ingress-controller",
		Routes: []*configpb.Route{{
			From: "https://from.example.com",
			To:   []string{"https://to.example.com"},
		}},
	})
	_, err = nodeA.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{Type: data.TypeUrl, Id: "ingress-controller", Data: data}},
	})
	require.NoError(t, err)

	// node-b can only take over once it has replicated the record
	cc, err := grpc.NewClient(listenerB.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	require.Eventually(t, func() bool {
		res, err := databrokerpb.NewDataBrokerServiceClient(cc).Get(
			databrokerpb.WithOutgoingClusterRequestMode(ctx, databrokerpb.ClusterRequestModeLocal),
			&databrokerpb.GetRequest{Type: data.TypeUrl, Id: "ingress-controller"})
		return err == nil && res.GetRecord() != nil
	}, 10*time.Second, 10*time.Millisecond, "node-b never replicated the config record")

	// the config source talks to node-a, as pomerium talks to its own node
	base := config.NewDefaultOptions()
	base.SharedKey = base64.StdEncoding.EncodeToString(sharedKey)
	baseCfg := config.New(base)
	_, baseCfg.OutboundPort, _ = net.SplitHostPort(listenerA.Addr().String())
	var mu sync.Mutex
	var published, withoutRoute int
	baseSource := config.NewStaticSource(baseCfg)
	src := NewConfigSource(ctx, noop.NewTracerProvider(), baseSource, EnableConfigValidation(true),
		func(_ context.Context, cfg *config.Config) {
			mu.Lock()
			defer mu.Unlock()
			published++
			if len(cfg.Options.AdditionalPolicies) == 0 {
				withoutRoute++
			}
		})
	require.Eventually(t, func() bool {
		return len(src.GetConfig().Options.AdditionalPolicies) == 1
	}, 10*time.Second, 10*time.Millisecond, "the config source never loaded the record")
	counts := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return published, withoutRoute
	}

	syncerTypes := []string{
		grpcutil.GetTypeURL(new(configpb.Config)),
		grpcutil.GetTypeURL(new(configpb.VersionedConfig)),
		grpcutil.GetTypeURL(new(configpb.KeyPair)),
		grpcutil.GetTypeURL(new(configpb.Policy)),
		grpcutil.GetTypeURL(new(configpb.Route)),
		grpcutil.GetTypeURL(new(configpb.Settings)),
	}
	resynced := func(since int) bool {
		callsMu.Lock()
		defer callsMu.Unlock()
		var aborted, fetched []string
		for _, c := range calls[since:] {
			switch {
			case c.method == "Sync" && c.code == codes.Aborted:
				aborted = append(aborted, c.typeURL)
			case c.method == "SyncLatest" && c.code == codes.OK && slices.Contains(aborted, c.typeURL):
				fetched = append(fetched, c.typeURL)
			}
		}
		for _, typeURL := range syncerTypes {
			if !slices.Contains(fetched, typeURL) {
				return false
			}
		}
		return true
	}

	// keep the config rebuilding, as the other syncers do while they re-sync
	stop := make(chan struct{})
	rebuilds := make(chan struct{})
	go func() {
		defer close(rebuilds)
		for {
			select {
			case <-stop:
				return
			default:
				baseSource.SetConfig(ctx, baseCfg.Clone())
			}
		}
	}()
	defer func() { close(stop); <-rebuilds }()

	const leaderChanges = 20
	for i := range leaderChanges {
		leaderID := []string{"node-b", "node-a"}[i%2]
		callsMu.Lock()
		since := len(calls)
		callsMu.Unlock()
		nodeB.OnConfigChange(ctx, nodeConfig("node-b", leaderID))
		nodeA.OnConfigChange(ctx, nodeConfig("node-a", leaderID))

		// every syncer is aborted and fetches its records again
		require.Eventuallyf(t, func() bool { return resynced(since) },
			10*time.Second, 10*time.Millisecond, "leader change %d (to %s) did not re-sync every syncer", i, leaderID)
		require.Eventuallyf(t, func() bool { return len(src.GetConfig().Options.AdditionalPolicies) == 1 },
			10*time.Second, 10*time.Millisecond, "leader change %d (to %s) never restored the config record", i, leaderID)
		// let the syncers apply what they fetched
		time.Sleep(20 * time.Millisecond)

		_, missing := counts()
		require.Zerof(t, missing,
			"leader change %d (to %s) published a config without the config record, although the record never changed",
			i, leaderID)
	}
}

type syncCall struct {
	method, typeURL string
	code            codes.Code
}

// typeRecordingServerStream records the record type a Sync or SyncLatest
// request asks for.
type typeRecordingServerStream struct {
	grpc.ServerStream
	typeURL string
}

func (s *typeRecordingServerStream) RecvMsg(m any) error {
	err := s.ServerStream.RecvMsg(m)
	if req, ok := m.(interface{ GetType() string }); ok {
		s.typeURL = req.GetType()
	}
	return err
}
