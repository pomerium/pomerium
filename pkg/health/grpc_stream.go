package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	healthpb "github.com/pomerium/pomerium/pkg/grpc/health"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	slicesutil "github.com/pomerium/pomerium/pkg/slices"
)

type GRPCStreamProvider struct {
	tr Tracker

	requiredChecks []Check
	batch          chan struct{}
	batchWindow    time.Duration

	subscribersMu *sync.RWMutex
	subscribers   map[string]chan struct{}

	ctx       context.Context
	cancel    context.CancelFunc
	sharedKey []byte
}

func NewGRPCStreamProvider(
	parentCtx context.Context,
	tr Tracker,
	batchWindow time.Duration,
	sharedKey []byte,
	options ...CheckOption,
) *GRPCStreamProvider {
	defaultOpts := &CheckOptions{}
	defaultOpts.Apply(options...)

	sp := &GRPCStreamProvider{
		tr:             tr,
		requiredChecks: slices.Collect(maps.Keys(defaultOpts.expected)),
		batchWindow:    batchWindow,
		batch:          make(chan struct{}, 1),
		subscribers:    make(map[string]chan struct{}),
		subscribersMu:  &sync.RWMutex{},
		sharedKey:      sharedKey,
	}
	sp.ctx, sp.cancel = context.WithCancel(parentCtx)
	go func() {
		sp.receiveBufferedUpdate()
	}()
	return sp
}

var (
	_ Provider                      = (*GRPCStreamProvider)(nil)
	_ healthpb.HealthNotifierServer = (*GRPCStreamProvider)(nil)
)

func (g *GRPCStreamProvider) receiveBufferedUpdate() {
	for {
	RETRY:
		select {
		case <-g.batch:
		case <-g.ctx.Done():
		}
		tc := time.After(g.batchWindow)
		for {
			select {
			case <-g.batch:
				// ignore
			case <-tc:
				g.subscribersMu.RLock()
				subscribers := g.subscribers
				for _, sub := range subscribers {
					// do not block
					select {
					case sub <- struct{}{}:
					default:
					}
				}
				g.subscribersMu.RUnlock()
				goto RETRY
			case <-g.ctx.Done():
				return
			}
		}
	}
}

func (g *GRPCStreamProvider) ReportStatus(Check, Status, ...Attr) {
	// prevent parent health manager from blocking
	select {
	case g.batch <- struct{}{}:
	default:
	}
}

func (g *GRPCStreamProvider) ReportError(Check, error, ...Attr) {
	// prevent parent health manager from blocking
	select {
	case g.batch <- struct{}{}:
	default:
	}
}

func (g *GRPCStreamProvider) authorize(ctx context.Context) error {
	return grpcutil.RequireSignedJWT(ctx, g.sharedKey)
}

func (g *GRPCStreamProvider) Close() {
	if g.cancel != nil {
		g.cancel()
	}
}

func (g *GRPCStreamProvider) SyncHealth(_ *healthpb.HealthStreamRequest, server grpc.ServerStreamingServer[healthpb.HealthMessage]) error {
	ctx := server.Context()
	id := uuid.New().String()
	ctx = log.Ctx(server.Context()).With().Str("stream-id", id).Logger().WithContext(ctx)
	if err := g.authorize(ctx); err != nil {
		log.Ctx(ctx).Err(err).Msg("failed to authorize stream")
		return err
	}
	t := time.NewTicker(time.Second * 90)
	defer t.Stop()
	// always send computed state on connect

	g.subscribersMu.Lock()
	recv := make(chan struct{}, 1)
	g.subscribers[id] = recv
	g.subscribersMu.Unlock()
	defer func() {
		g.subscribersMu.Lock()
		delete(g.subscribers, id)
		g.subscribersMu.Unlock()
	}()
	log.Ctx(ctx).Debug().Msg("sending initial health message")
	sendErr := server.Send(g.currentStateAsProto())
	if errors.Is(sendErr, io.EOF) {
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}

	for {
		select {
		case <-t.C:
			log.Ctx(ctx).Debug().Msg("sending periodic health update to remote")
			sendErr := server.Send(g.currentStateAsProto())
			if errors.Is(sendErr, io.EOF) {
				return status.Error(codes.DeadlineExceeded, "deadline exceeded")
			} else if sendErr != nil {
				log.Ctx(ctx).Err(sendErr).Msg("failed to stream periodic health update to remote server")
			}
		case <-recv:
			log.Ctx(ctx).Debug().Msg("sending health update to remote")
			sendErr := server.Send(g.currentStateAsProto())
			if errors.Is(sendErr, io.EOF) {
				return status.Error(codes.DeadlineExceeded, "deadline exceeded")
			} else if sendErr != nil {
				log.Ctx(ctx).Err(sendErr).Msg("failed to stream health update to remote server")
			}
		case <-g.ctx.Done():
			if err := g.ctx.Err(); err != nil {
				return status.Error(codes.FailedPrecondition, fmt.Sprintf("server done : %s", err.Error()))
			}
			return status.Error(codes.FailedPrecondition, "server done")
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "server done")
		}
	}
}

func (g *GRPCStreamProvider) currentStateAsProto() *healthpb.HealthMessage {
	return ConvertRecordsToPb(g.tr.GetRecords(), g.requiredChecks)
}

func ConvertRecordsToPb(in map[Check]*Record, required []Check) *healthpb.HealthMessage {
	st := map[string]*healthpb.ComponentStatus{}
	for check, rec := range in {
		msg := &healthpb.ComponentStatus{
			Status:     ConvertStatusToPb(rec.Status()),
			Attributes: asMap(rec.Attr()),
		}
		if err := rec.Err(); err != nil {
			msg.Err = proto.String(err.Error())
		}

		st[string(check)] = msg
	}
	var overallStatus healthpb.OverallStatus
	maxStatus := StatusUnknown
	notFound := []string{}
	notHealthy := []string{}
	for _, req := range required {
		rec, ok := in[req]
		if !ok {
			notFound = append(notFound, string(req))
			continue
		}
		if rec.Err() != nil {
			notHealthy = append(notHealthy, string(req))
		}
		if rec.Status() > maxStatus {
			maxStatus = rec.Status()
		}
	}

	sort.Strings(notFound)
	sort.Strings(notHealthy)

	var overallErr *string
	if len(notFound) > 0 {
		overallStatus = healthpb.OverallStatus_OVERALL_STATUS_STARTING
		overallErr = proto.String(fmt.Sprintf(
			"%d component(s) not started: %s", len(notFound), strings.Join(notFound, ","),
		))
	} else {
		overallStatus = healthpb.OverallStatus_OVERALL_STATUS_RUNNING
	}
	if maxStatus == StatusTerminating {
		overallStatus = healthpb.OverallStatus_OVERALL_STATUS_TERMINATING
	}
	if overallErr == nil && len(notHealthy) > 0 {
		overallErr = proto.String(
			fmt.Sprintf("%d component(s) not healthy: %s", len(notHealthy), strings.Join(notHealthy, ",")),
		)
	}

	req := slicesutil.Map(required, func(c Check) string {
		return string(c)
	})
	sort.Strings(req)

	return &healthpb.HealthMessage{
		OverallStatus: overallStatus,
		OverallErr:    overallErr,
		Statuses:      st,
		Required:      req,
	}
}

func asMap(in []Attr) map[string]string {
	ret := map[string]string{}
	for _, entry := range in {
		ret[entry.Key] = entry.Value
	}
	return ret
}

func ConvertStatusToPb(s Status) healthpb.HealthStatus {
	switch s {
	case StatusRunning:
		return healthpb.HealthStatus_HEALTH_STATUS_RUNNING
	case StatusTerminating:
		return healthpb.HealthStatus_HEALTH_STATUS_TERMINATING
	default:
		return healthpb.HealthStatus_HEALTH_STATUS_UNKNOWN
	}
}
