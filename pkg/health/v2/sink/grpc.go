package sink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	healthpb "github.com/pomerium/pomerium/pkg/grpc/health"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

const grpcPeriodicUpdate = 90 * time.Second

type GRPC struct {
	latest      *latestSnapshot
	batchWindow time.Duration
	sharedKey   []byte

	subscribersMu sync.RWMutex
	subscribers   map[string]chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
}

var (
	_ healthv2.HealthSink           = (*GRPC)(nil)
	_ healthpb.HealthNotifierServer = (*GRPC)(nil)
)

func NewGRPC(batchWindow time.Duration, sharedKey []byte) *GRPC {
	g := &GRPC{
		latest:      newLatestSnapshot(),
		batchWindow: batchWindow,
		sharedKey:   sharedKey,
		subscribers: map[string]chan struct{}{},
	}
	g.ctx, g.cancel = context.WithCancel(context.Background())
	go g.broadcastBatches()
	return g
}

func (g *GRPC) Notify(snap healthv2.Snapshot) { g.latest.store(snap) }

func (g *GRPC) Close() { g.cancel() }

func (g *GRPC) broadcastBatches() {
	for {
		select {
		case <-g.latest.signal:
		case <-g.ctx.Done():
			return
		}
		select {
		case <-time.After(g.batchWindow):
		case <-g.ctx.Done():
			return
		}
		select {
		case <-g.latest.signal:
		default:
		}
		g.broadcast()
	}
}

func (g *GRPC) broadcast() {
	g.subscribersMu.RLock()
	defer g.subscribersMu.RUnlock()
	for _, sub := range g.subscribers {
		select {
		case sub <- struct{}{}:
		default:
		}
	}
}

func (g *GRPC) subscribe(id string) <-chan struct{} {
	recv := make(chan struct{}, 1)
	g.subscribersMu.Lock()
	g.subscribers[id] = recv
	g.subscribersMu.Unlock()
	return recv
}

func (g *GRPC) unsubscribe(id string) {
	g.subscribersMu.Lock()
	delete(g.subscribers, id)
	g.subscribersMu.Unlock()
}

func (g *GRPC) SyncHealth(_ *healthpb.HealthStreamRequest, server grpc.ServerStreamingServer[healthpb.HealthMessage]) error {
	id := uuid.New().String()
	ctx := log.Ctx(server.Context()).With().Str("stream-id", id).Logger().WithContext(server.Context())
	if err := grpcutil.RequireSignedJWT(ctx, g.sharedKey); err != nil {
		log.Ctx(ctx).Err(err).Msg("failed to authorize stream")
		return err
	}

	recv := g.subscribe(id)
	defer g.unsubscribe(id)
	t := time.NewTicker(grpcPeriodicUpdate)
	defer t.Stop()

	send := func(reason string) error {
		log.Ctx(ctx).Debug().Msgf("sending %s health message", reason)
		err := server.Send(snapshotToPb(g.latest.load()))
		if errors.Is(err, io.EOF) {
			return status.Error(codes.DeadlineExceeded, "deadline exceeded")
		} else if err != nil {
			log.Ctx(ctx).Err(err).Msgf("failed to stream %s health message", reason)
		}
		return nil
	}

	if err := send("initial"); err != nil {
		return err
	}
	for {
		var err error
		select {
		case <-t.C:
			err = send("periodic")
		case <-recv:
			err = send("updated")
		case <-g.ctx.Done():
			return status.Error(codes.FailedPrecondition, fmt.Sprintf("server done : %s", g.ctx.Err()))
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "server done")
		}
		if err != nil {
			return err
		}
	}
}

func snapshotToPb(snap healthv2.Snapshot) *healthpb.HealthMessage {
	statuses := map[string]*healthpb.ComponentStatus{}
	var notFound, notHealthy []string
	maxStatus := check.StatusUnknown
	for _, c := range snap.Checkers {
		for _, r := range c.Results {
			if !r.Reported() {
				notFound = append(notFound, string(r.Name))
				continue
			}
			msg := &healthpb.ComponentStatus{
				Status:     statusToPb(r.Status),
				Attributes: attrsToMap(r.Attrs),
			}
			if r.Err != nil {
				msg.Err = new(r.Err.Error())
				notHealthy = append(notHealthy, string(r.Name))
			}
			statuses[string(r.Name)] = msg
			maxStatus = max(maxStatus, r.Status)
		}
	}
	slices.Sort(notFound)
	slices.Sort(notHealthy)

	msg := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_OVERALL_STATUS_RUNNING,
		Statuses:      statuses,
		Required:      snap.Required(),
	}
	if !snap.Configured {
		msg.OverallStatus = healthpb.OverallStatus_OVERALL_STATUS_STARTING
	} else if len(notFound) > 0 {
		msg.OverallStatus = healthpb.OverallStatus_OVERALL_STATUS_STARTING
		msg.OverallErr = new(fmt.Sprintf("%d component(s) not started: %s", len(notFound), strings.Join(notFound, ",")))
	} else if len(notHealthy) > 0 {
		msg.OverallErr = new(fmt.Sprintf("%d component(s) not healthy: %s", len(notHealthy), strings.Join(notHealthy, ",")))
	}
	if maxStatus == check.StatusTerminating {
		msg.OverallStatus = healthpb.OverallStatus_OVERALL_STATUS_TERMINATING
	}
	return msg
}

func statusToPb(s check.Status) healthpb.HealthStatus {
	switch s {
	case check.StatusRunning:
		return healthpb.HealthStatus_HEALTH_STATUS_RUNNING
	case check.StatusTerminating:
		return healthpb.HealthStatus_HEALTH_STATUS_TERMINATING
	default:
		return healthpb.HealthStatus_HEALTH_STATUS_UNKNOWN
	}
}

func attrsToMap(attrs []check.Attr) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		m[a.Key] = a.Value
	}
	return m
}
