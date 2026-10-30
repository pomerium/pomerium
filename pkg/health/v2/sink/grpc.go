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
)

const grpcPeriodicUpdate = 90 * time.Second

type GRPC struct {
	latest      *latestSnapshot
	batchWindow time.Duration
	sharedKey   func() []byte

	subscribersMu sync.RWMutex
	subscribers   map[string]chan struct{}

	ctx context.Context
}

var (
	_ healthv2.HealthSink           = (*GRPC)(nil)
	_ healthpb.HealthNotifierServer = (*GRPC)(nil)
)

func NewGRPC(batchWindow time.Duration, sharedKey func() []byte) *GRPC {
	return &GRPC{
		latest:      newLatestSnapshot(),
		batchWindow: batchWindow,
		sharedKey:   sharedKey,
		subscribers: map[string]chan struct{}{},
		ctx:         context.Background(),
	}
}

func (g *GRPC) Run() { go g.broadcastBatches() }

func (g *GRPC) Notify(snap healthv2.Snapshot) { g.latest.store(snap) }

func (g *GRPC) Shutdown(context.Context) {}

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
	if err := grpcutil.RequireSignedJWT(ctx, g.sharedKey()); err != nil {
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
	var starting, notReady, unhealthy []string
	for _, c := range snap.Checkers {
		statuses[c.Key()] = checkerToPb(c)
		switch {
		case !c.Initialized.OK:
			starting = append(starting, c.Key())
		case !c.Ready.OK:
			notReady = append(notReady, c.Key())
		}
		if !c.Healthy.OK {
			unhealthy = append(unhealthy, c.Key())
		}
	}
	slices.Sort(starting)
	slices.Sort(notReady)
	slices.Sort(unhealthy)

	msg := &healthpb.HealthMessage{
		OverallStatus: healthpb.OverallStatus_OVERALL_STATUS_RUNNING,
		OverallErr:    overallErr(starting, notReady, unhealthy),
		Statuses:      statuses,
		Required:      snap.Keys(),
	}
	if !snap.Initialized() {
		msg.OverallStatus = healthpb.OverallStatus_OVERALL_STATUS_STARTING
	}
	return msg
}

func overallErr(starting, notReady, unhealthy []string) *string {
	var parts []string
	if len(starting) > 0 {
		parts = append(parts, fmt.Sprintf("%d component(s) starting: %s", len(starting), strings.Join(starting, ",")))
	}
	if len(notReady) > 0 {
		parts = append(parts, fmt.Sprintf("%d component(s) not ready: %s", len(notReady), strings.Join(notReady, ",")))
	}
	if len(unhealthy) > 0 {
		parts = append(parts, fmt.Sprintf("%d component(s) not healthy: %s", len(unhealthy), strings.Join(unhealthy, ",")))
	}
	if len(parts) == 0 {
		return nil
	}
	return new(strings.Join(parts, "; "))
}

func checkerToPb(c healthv2.CheckerStatus) *healthpb.ComponentStatus {
	msg := &healthpb.ComponentStatus{
		Status:      stateToPb(c.State()),
		Attributes:  map[string]string{},
		Initialized: conditionToPb(c.Initialized),
		Ready:       conditionToPb(c.Ready),
		Healthy:     conditionToPb(c.Healthy),
	}
	if reason, failed := c.Reason(); failed {
		msg.Err = new(reason)
	}
	for k, v := range c.Initialized.Info.Details {
		msg.Attributes["initialized."+k] = v
	}
	for k, v := range c.Ready.Info.Details {
		msg.Attributes["ready."+k] = v
	}
	for k, v := range c.Healthy.Info.Details {
		msg.Attributes["healthy."+k] = v
	}
	return msg
}

func conditionToPb(c healthv2.Condition) *healthpb.Condition {
	msg := &healthpb.Condition{Ok: c.OK}
	if !c.OK && c.Info.Reason != "" {
		msg.Reason = new(c.Info.Reason)
	}
	return msg
}

func stateToPb(s healthv2.State) healthpb.HealthStatus {
	switch s {
	case healthv2.StateOK:
		return healthpb.HealthStatus_HEALTH_STATUS_RUNNING
	case healthv2.StateStarting:
		return healthpb.HealthStatus_HEALTH_STATUS_STARTING
	case healthv2.StateNotReady:
		return healthpb.HealthStatus_HEALTH_STATUS_NOT_READY
	case healthv2.StateUnhealthy:
		return healthpb.HealthStatus_HEALTH_STATUS_UNHEALTHY
	default:
		return healthpb.HealthStatus_HEALTH_STATUS_UNKNOWN
	}
}
