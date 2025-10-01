package databroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/health"
)

var (
	errClusteredFollowerServerStopped = errors.New("stopped")
	errClusteredFollowerNeedsReset    = errors.New("needs reset")
)

type clusteredFollowerServer struct {
	telemetry telemetry.Component
	leaderCC  grpc.ClientConnInterface
	leader    Server
	local     Server

	cancel context.CancelCauseFunc
}

// NewClusteredFollowerServer creates a new clustered follower databroker
// server. A clustered follower server forwards all requests to a leader
// databroker via the passed client connection.
func NewClusteredFollowerServer(tracerProvider oteltrace.TracerProvider, local Server, leaderCC grpc.ClientConnInterface) Server {
	srv := &clusteredFollowerServer{
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.DebugLevel, "databroker-clustered-follower-server"),
		leaderCC:  leaderCC,
		leader:    NewForwardingServer(leaderCC),
		local:     local,
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

func (srv *clusteredFollowerServer) GetCheckpoint(ctx context.Context, req *databrokerpb.GetCheckpointRequest) (res *databrokerpb.GetCheckpointResponse, err error) {
	return srv.local.GetCheckpoint(ctx, req)
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

func (srv *clusteredFollowerServer) SetCheckpoint(_ context.Context, _ *databrokerpb.SetCheckpointRequest) (*databrokerpb.SetCheckpointResponse, error) {
	return nil, databrokerpb.ErrSetCheckpointNotSupported
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
	b := backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0))
	for {
		// attempt to sync
		err := srv.sync(ctx, b)

		// if we need to reset, call sync latest and then sync again
		if errors.Is(err, errClusteredFollowerNeedsReset) {
			err = srv.syncLatest(ctx, b)
			if err == nil {
				err = srv.sync(ctx, b)
			}
		}

		// backoff and retry
		delay := b.NextBackOff()
		log.Ctx(ctx).Error().
			Err(err).
			Dur("delay", delay).
			Msg("databroker-clustered-follower-server: error syncing records")
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (srv *clusteredFollowerServer) healthAttrs() []health.Attr {
	return []health.Attr{
		health.StrAttr("member", "follower"),
	}
}

// sync syncs records from the leader and stores them in the local store.
func (srv *clusteredFollowerServer) sync(ctx context.Context, b backoff.BackOff) error {
	// run a 3 step pipeline:
	// - sync records
	// - batch the records and track the latest checkpoint
	// - put the records and checkpoint
	ch1 := make(chan clusteredFollowerServerBatchStepPayload, 1)
	ch2 := make(chan clusteredFollowerServerPutStepPayload, 1)
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { defer close(ch1); return srv.syncStep(ctx, b, ch1) })
	eg.Go(func() error { defer close(ch2); return srv.batchStep(ctx, ch1, ch2) })
	eg.Go(func() error { return srv.putStep(ctx, ch2) })
	err := eg.Wait()
	if err == nil {
		health.ReportRunning(health.DatabrokerCluster, srv.healthAttrs()...)
	} else {
		health.ReportError(health.DatabrokerCluster, err, srv.healthAttrs()...)
	}
	return err
}

// syncLatest resets the local store, syncs the latest records from the leader,
// and stores them in the local store.
func (srv *clusteredFollowerServer) syncLatest(ctx context.Context, b backoff.BackOff) error {
	// run a 3 step pipeline:
	// - sync the latest records
	// - batch the records and track the latest checkpoint
	// - put the records and checkpoint
	ch1 := make(chan clusteredFollowerServerBatchStepPayload, 1)
	ch2 := make(chan clusteredFollowerServerPutStepPayload, 1)
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { defer close(ch1); return srv.syncLatestStep(ctx, b, ch1) })
	eg.Go(func() error { defer close(ch2); return srv.batchStep(ctx, ch1, ch2) })
	eg.Go(func() error { return srv.putStep(ctx, ch2) })
	err := eg.Wait()
	if err == nil {
		health.ReportRunning(health.DatabrokerCluster, srv.healthAttrs()...)
	} else {
		health.ReportError(health.DatabrokerCluster, err, srv.healthAttrs()...)
	}
	return err
}

// syncStep starts a sync stream and sends records and checkpoints to the
// batch step.
func (srv *clusteredFollowerServer) syncStep(
	ctx context.Context,
	b backoff.BackOff,
	out chan<- clusteredFollowerServerBatchStepPayload,
) error {
	// get the current checkpoint
	checkpointResponse, err := srv.local.GetCheckpoint(ctx, new(databrokerpb.GetCheckpointRequest))
	if err != nil {
		return fmt.Errorf("error retrieving checkpoint: %w", err)
	} else if checkpointResponse.Checkpoint.ServerVersion == 0 {
		// there is no current checkpoint so we need to reset and call sync
		// latest
		return errClusteredFollowerNeedsReset
	}
	checkpoint := checkpointResponse.Checkpoint

	// cancel the stream if we return
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// start the stream
	client := databrokerpb.NewDataBrokerServiceClient(srv.leaderCC)
	stream, err := client.Sync(ctx, &databrokerpb.SyncRequest{
		ServerVersion: checkpoint.ServerVersion,
		RecordVersion: checkpoint.RecordVersion,
	})
	if err != nil {
		return fmt.Errorf("error starting sync stream: %w", err)
	}

	for {
		res, err := stream.Recv()
		if status.Code(err) == codes.Aborted {
			// this indicates we need to reset and use sync latest to get the
			// latest records
			return errClusteredFollowerNeedsReset
		} else if err != nil {
			return fmt.Errorf("error receiving sync message: %w", err)
		}

		b.Reset()

		// clone the checkpoint to avoid a data race from the next step
		checkpoint = proto.CloneOf(checkpoint)
		checkpoint.RecordVersion = max(checkpoint.RecordVersion, res.Record.Version)
		payload := clusteredFollowerServerBatchStepPayload{
			checkpoint: checkpoint,
			record:     res.Record,
		}

		// send the batch payload
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case out <- payload:
		}
	}
}

// syncLatestStep starts a sync latest stream and sends records and
// checkpoints to the batch step.
func (srv *clusteredFollowerServer) syncLatestStep(
	ctx context.Context,
	b backoff.BackOff,
	out chan<- clusteredFollowerServerBatchStepPayload,
) error {
	ctx, op := srv.telemetry.Start(ctx, "SyncLatestStep")
	defer op.Complete()

	log.Ctx(ctx).Info().Msg("resyncing")

	// reset the local store
	_, err := srv.local.Clear(ctx, new(emptypb.Empty))
	if err != nil {
		return op.Failure(fmt.Errorf("error clearing existing records: %w", err))
	}

	// cancel the stream if we return
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// start the stream
	client := databrokerpb.NewDataBrokerServiceClient(srv.leaderCC)
	stream, err := client.SyncLatest(ctx, &databrokerpb.SyncLatestRequest{})
	if err != nil {
		return op.Failure(fmt.Errorf("error starting sync latest stream: %w", err))
	}

	var serverVersion, latestRecordVersion uint64
	cnt := 0
	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			// this indicates the stream is complete
			break
		} else if err != nil {
			return op.Failure(fmt.Errorf("error receiving sync latest message: %w", err))
		}

		// create a batch payload based on the message
		var payload clusteredFollowerServerBatchStepPayload
		switch res := res.Response.(type) {
		case *databrokerpb.SyncLatestResponse_Record:
			cnt++
			payload.record = res.Record
		case *databrokerpb.SyncLatestResponse_Versions:
			serverVersion = res.Versions.ServerVersion
			latestRecordVersion = res.Versions.LatestRecordVersion
			payload.checkpoint = &databrokerpb.Checkpoint{
				ServerVersion: res.Versions.ServerVersion,
				RecordVersion: res.Versions.LatestRecordVersion,
			}
		default:
			return op.Failure(fmt.Errorf("unknown message type from sync latest: %T", res))
		}

		// send the batch payload
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case out <- payload:
		}
	}

	log.Ctx(ctx).Info().
		Int("record-count", cnt).
		Uint64("server-version", serverVersion).
		Uint64("latest-record-version", latestRecordVersion).
		Msg("synced latest records")

	b.Reset()
	return nil
}

func (srv *clusteredFollowerServer) batchStep(
	ctx context.Context,
	in <-chan clusteredFollowerServerBatchStepPayload,
	out chan<- clusteredFollowerServerPutStepPayload,
) error {
	const batchSize = 64
	const maxWait = time.Second

	// start a ticker so we don't wait too long between batches
	ticker := time.NewTicker(maxWait)
	defer ticker.Stop()
	// pre-allocate the batch
	batch := clusteredFollowerServerPutStepPayload{
		records: make([]*databrokerpb.Record, 0, batchSize),
	}
	// send sends the batch to the out channel and reset it
	send := func() error {
		// don't send an empty batch
		if batch.checkpoint == nil && len(batch.records) == 0 {
			return nil
		}

		// send the batch
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case out <- batch:
		}

		// reset the batch
		batch.checkpoint = nil
		batch.records = make([]*databrokerpb.Record, 0, batchSize)
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case payload, ok := <-in:
			// if the channel was closed, send the last batch and return
			if !ok {
				return send()
			}

			if payload.record != nil {
				batch.records = append(batch.records, payload.record)
			}
			if payload.checkpoint != nil {
				batch.checkpoint = payload.checkpoint
			}

			// if we've hit the batch size, send the batch
			if len(batch.records) == batchSize {
				if err := send(); err != nil {
					return err
				}
			}
		case <-ticker.C:
			// send the batch as we've waited too long
			if err := send(); err != nil {
				return err
			}
		}
	}
}

func (srv *clusteredFollowerServer) putStep(
	ctx context.Context,
	in <-chan clusteredFollowerServerPutStepPayload,
) error {
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case payload, ok := <-in:
			// if the in channel was closed, just return
			if !ok {
				return nil
			}

			// if there are records, put them in the local store
			if len(payload.records) > 0 {
				_, err := srv.local.Put(ctx, &databrokerpb.PutRequest{
					Records: payload.records,
				})
				if err != nil {
					return fmt.Errorf("error storing local records: %w", err)
				}
			}

			// if there is a checkpoint, set it in the local store
			if payload.checkpoint != nil {
				_, err := srv.local.SetCheckpoint(ctx, &databrokerpb.SetCheckpointRequest{
					Checkpoint: payload.checkpoint,
				})
				if err != nil {
					return fmt.Errorf("error setting local checkpoint: %w", err)
				}
			}
		}
	}
}

type clusteredFollowerServerBatchStepPayload struct {
	checkpoint *databrokerpb.Checkpoint
	record     *databrokerpb.Record
}

type clusteredFollowerServerPutStepPayload struct {
	checkpoint *databrokerpb.Checkpoint
	records    []*databrokerpb.Record
}
