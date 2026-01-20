package databroker

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/health"
)

type clusteredLeaderServer struct {
	local    Server
	onChange *signal.Signal

	cancel context.CancelCauseFunc
}

// NewClusteredLeaderServer creates a new clustered leader databroker server.
// A clustered leader server implements the server interface via a local
// backend server.
func NewClusteredLeaderServer(local Server) Server {
	health.ReportRunning(health.DatabrokerCluster, health.StrAttr("member", "leader"))
	srv := &clusteredLeaderServer{
		local: local,
		onChange: signal.New(
			signal.WithLogger(log.Logger()),
		),
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	srv.cancel = cancel
	go srv.run(ctx)
	return srv
}

func (srv *clusteredLeaderServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (res *databrokerpb.AcquireLeaseResponse, err error) {
	return srv.local.AcquireLease(ctx, req)
}

func (srv *clusteredLeaderServer) Clear(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ClearResponse, err error) {
	defer srv.onChange.Broadcast(ctx)
	return srv.local.Clear(ctx, req)
}

func (srv *clusteredLeaderServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (res *databrokerpb.GetResponse, err error) {
	return srv.local.Get(ctx, req)
}

func (srv *clusteredLeaderServer) GetCheckpoint(ctx context.Context, req *databrokerpb.GetCheckpointRequest) (res *databrokerpb.GetCheckpointResponse, err error) {
	res, err = srv.local.GetCheckpoint(ctx, req)
	if err != nil {
		return nil, err
	}
	res.IsLeader = true
	return res, nil
}

func (srv *clusteredLeaderServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	return srv.local.List(ctx, req)
}

func (srv *clusteredLeaderServer) ListTypes(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ListTypesResponse, err error) {
	return srv.local.ListTypes(ctx, req)
}

func (srv *clusteredLeaderServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (res *databrokerpb.PatchResponse, err error) {
	defer srv.onChange.Broadcast(ctx)
	return srv.local.Patch(ctx, req)
}

func (srv *clusteredLeaderServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (res *databrokerpb.PutResponse, err error) {
	defer srv.onChange.Broadcast(ctx)
	return srv.local.Put(ctx, req)
}

func (srv *clusteredLeaderServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (res *databrokerpb.QueryResponse, err error) {
	return srv.local.Query(ctx, req)
}

func (srv *clusteredLeaderServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (res *emptypb.Empty, err error) {
	return srv.local.ReleaseLease(ctx, req)
}

func (srv *clusteredLeaderServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (res *emptypb.Empty, err error) {
	return srv.local.RenewLease(ctx, req)
}

func (srv *clusteredLeaderServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	return srv.local.Report(ctx, req)
}

func (srv *clusteredLeaderServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	return srv.local.ServerInfo(ctx, req)
}

func (srv *clusteredLeaderServer) SetCheckpoint(_ context.Context, _ *databrokerpb.SetCheckpointRequest) (*databrokerpb.SetCheckpointResponse, error) {
	return nil, databrokerpb.ErrSetCheckpointNotSupported
}

func (srv *clusteredLeaderServer) GetOptions(ctx context.Context, req *databrokerpb.GetOptionsRequest) (res *databrokerpb.GetOptionsResponse, err error) {
	return srv.local.GetOptions(ctx, req)
}

func (srv *clusteredLeaderServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (res *databrokerpb.SetOptionsResponse, err error) {
	defer srv.onChange.Broadcast(ctx)
	return srv.local.SetOptions(ctx, req)
}

func (srv *clusteredLeaderServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return srv.local.Sync(req, stream)
}

func (srv *clusteredLeaderServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return srv.local.SyncLatest(req, stream)
}

func (srv *clusteredLeaderServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return srv.local.Watch(req, stream)
}

func (srv *clusteredLeaderServer) Stop() {
	srv.cancel(nil)
}

func (srv *clusteredLeaderServer) OnConfigChange(_ context.Context, _ *config.Config) {}

func (srv *clusteredLeaderServer) run(ctx context.Context) {
	ch := srv.onChange.Bind()
	defer srv.onChange.Unbind(ch)
	for {
		// retrieve the current server info
		res, err := srv.local.ServerInfo(ctx, new(emptypb.Empty))
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker-clustered-leader-server: error retrieving current server info")
			continue
		}

		// set the checkpoint to the current server version and latest record version
		_, err = srv.local.SetCheckpoint(ctx, &databrokerpb.SetCheckpointRequest{
			Checkpoint: &databrokerpb.Checkpoint{
				ServerVersion: res.GetServerVersion(),
				RecordVersion: res.GetLatestRecordVersion(),
			},
		})
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker-clustered-leader-server: error updating checkpoint")
			continue
		}

		// wait for a change
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
	}
}
