package databroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var (
	errClusteredFollowerServerStopped = errors.New("stopped")
	errClusteredFollowerNeedsReset    = errors.New("needs reset")
)

type clusteredFollowerServer struct {
	leaderCC grpc.ClientConnInterface
	leader   Server
	local    Server

	cancel context.CancelCauseFunc
}

// NewClusteredFollowerServer creates a new clustered follower databroker
// server. A clustered follower server forwards all requests to a leader
// databroker via the passed client connection.
func NewClusteredFollowerServer(local Server, leaderCC grpc.ClientConnInterface) Server {
	srv := &clusteredFollowerServer{
		leaderCC: leaderCC,
		leader:   NewForwardingServer(leaderCC),
		local:    local,
	}
	ctx := context.Background()
	ctx, srv.cancel = context.WithCancelCause(ctx)
	go srv.run(ctx)
	return srv
}

func (srv *clusteredFollowerServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (res *databrokerpb.AcquireLeaseResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.AcquireLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Clear(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ClearResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.Clear(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (res *databrokerpb.GetResponse, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.Get(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.List(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ListTypes(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ListTypesResponse, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.ListTypes(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (res *databrokerpb.PatchResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.Patch(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (res *databrokerpb.PutResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.Put(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (res *databrokerpb.QueryResponse, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.Query(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (res *emptypb.Empty, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.ReleaseLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (res *emptypb.Empty, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.RenewLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.Report(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.ServerInfo(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (res *databrokerpb.SetOptionsResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.SetOptions(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return srv.invokeReadOnly(stream.Context(), func(handler Server) error {
		return handler.Sync(req, stream)
	})
}

func (srv *clusteredFollowerServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return srv.invokeReadOnly(stream.Context(), func(handler Server) error {
		return handler.SyncLatest(req, stream)
	})
}

func (srv *clusteredFollowerServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return srv.invokeReadOnly(stream.Context(), func(handler Server) error {
		return handler.Watch(req, stream)
	})
}

func (srv *clusteredFollowerServer) Stop() {
	srv.cancel(errClusteredFollowerServerStopped)
}

func (srv *clusteredFollowerServer) OnConfigChange(_ context.Context, _ *config.Config) {}

func (srv *clusteredFollowerServer) invokeReadOnly(ctx context.Context, fn func(handler Server) error) error {
	switch databrokerpb.GetIncomingClusterRequestMode(ctx) {
	case databrokerpb.ClusterRequestModeDefault:
		// forward to leader
		return fn(srv.leader)
	case databrokerpb.ClusterRequestModeLeader:
		// not a leader, so error out
		return databrokerpb.ErrNodeIsNotLeader
	case databrokerpb.ClusterRequestModeLocal:
		// send to local
		return fn(srv.local)
	default:
		return databrokerpb.ErrUnknownClusterRequestMode
	}
}

func (srv *clusteredFollowerServer) invokeReadWrite(ctx context.Context, fn func(handler Server) error) error {
	switch databrokerpb.GetIncomingClusterRequestMode(ctx) {
	case databrokerpb.ClusterRequestModeDefault:
		// forward to leader
		return fn(srv.leader)
	case databrokerpb.ClusterRequestModeLeader:
		// not a leader, so error out
		return databrokerpb.ErrNodeIsNotLeader
	case databrokerpb.ClusterRequestModeLocal:
		// not a leader and it's not safe to modify the local, so error out
		return databrokerpb.ErrNodeIsNotLeader
	default:
		return databrokerpb.ErrUnknownClusterRequestMode
	}
}

func (srv *clusteredFollowerServer) run(ctx context.Context) {
	bo := backoff.WithContext(backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0)), ctx)
	_ = backoff.RetryNotify(func() error {
		err := srv.sync(ctx)
		// if we need to reset, call sync latest, then sync again
		if errors.Is(err, errClusteredFollowerNeedsReset) {
			err = srv.syncLatest(ctx)
			if err == nil {
				err = srv.sync(ctx)
			}
		}
		// if the server is stopped, stop the backoff loop
		if errors.Is(err, errClusteredFollowerServerStopped) {
			return backoff.Permanent(err)
		}
		return err
	}, bo, func(err error, d time.Duration) {
		log.Ctx(ctx).Error().
			Err(err).
			Dur("delay", d).
			Msg("databroker-clustered-follower-server: error syncing records")
	})
}

func (srv *clusteredFollowerServer) sync(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	versionsRes, err := srv.local.Get(ctx, &databrokerpb.GetRequest{
		Type: clusteredFollowerServerVersionsType,
		Id:   clusteredFollowerServerVersionsID,
	})
	if status.Code(err) == codes.NotFound {
		return errClusteredFollowerNeedsReset
	} else if err != nil {
		return fmt.Errorf("error retrieving versions: %w", err)
	}
	versionsRecord := versionsRes.GetRecord()

	var versions databrokerpb.Versions
	err = versionsRecord.GetData().UnmarshalTo(&versions)
	if err != nil {
		return fmt.Errorf("error unmarshaling versions: %w", err)
	}

	client := databrokerpb.NewDataBrokerServiceClient(srv.leaderCC)
	stream, err := client.Sync(ctx, &databrokerpb.SyncRequest{
		ServerVersion: versions.GetServerVersion(),
		RecordVersion: versions.GetLatestRecordVersion(),
	})
	if err != nil {
		return fmt.Errorf("error starting sync stream: %w", err)
	}

	for {
		res, err := stream.Recv()
		if status.Code(err) == codes.Aborted {
			return errClusteredFollowerNeedsReset
		} else if err != nil {
			return fmt.Errorf("error receiving sync latest message: %w", err)
		}

		versions.LatestRecordVersion = max(versions.LatestRecordVersion, res.Record.Version)
		records := make([]*databrokerpb.Record, 0, 2)
		records = append(records, &databrokerpb.Record{
			Type: clusteredFollowerServerVersionsType,
			Id:   clusteredFollowerServerVersionsID,
			Data: protoutil.NewAny(&versions),
		})
		// ignore the clustered follower server versions type
		if res.Record.GetType() != clusteredFollowerServerVersionsType {
			records = append(records, res.Record)
		}

		_, err = srv.local.Put(ctx, &databrokerpb.PutRequest{
			Records: records,
		})
		if err != nil {
			return fmt.Errorf("error storing record from sync stream: %w", err)
		}
	}
}

func (srv *clusteredFollowerServer) syncLatest(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	_, err := srv.local.Clear(ctx, new(emptypb.Empty))
	if err != nil {
		return fmt.Errorf("error clearing existing records: %w", err)
	}

	client := databrokerpb.NewDataBrokerServiceClient(srv.leaderCC)
	stream, err := client.SyncLatest(ctx, &databrokerpb.SyncLatestRequest{})
	if err != nil {
		return fmt.Errorf("error starting sync latest stream: %w", err)
	}

	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("error receiving sync latest message: %w", err)
		}

		switch res := res.Response.(type) {
		case *databrokerpb.SyncLatestResponse_Record:
			_, err = srv.local.Put(ctx, &databrokerpb.PutRequest{
				Records: []*databrokerpb.Record{res.Record},
			})
			if err != nil {
				return fmt.Errorf("error storing record from sync latest stream: %w", err)
			}
		case *databrokerpb.SyncLatestResponse_Versions:
			_, err = srv.local.Put(ctx, &databrokerpb.PutRequest{
				Records: []*databrokerpb.Record{{
					Type: clusteredFollowerServerVersionsType,
					Id:   clusteredFollowerServerVersionsID,
					Data: protoutil.NewAny(res.Versions),
				}},
			})
			if err != nil {
				return fmt.Errorf("error storing versions from sync latest stream: %w", err)
			}
		default:
			return fmt.Errorf("unknown message type from sync latest: %T", res)
		}
	}

	return nil
}

const (
	clusteredFollowerServerVersionsType = "pomerium.io/ClusteredFollowerServerVersions"
	clusteredFollowerServerVersionsID   = "local"
)
