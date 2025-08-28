package databroker

import (
	"context"
	"errors"
	"sync"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	internalmetrics "github.com/pomerium/pomerium/internal/telemetry/metrics"
	metrics "github.com/pomerium/pomerium/pkg/metrics"
	"github.com/pomerium/pomerium/pkg/slices"
)

// fastForwardHandler will skip
type fastForwardHandler struct {
	id      string
	handler SyncerHandler
	pending chan ffCmd

	mu sync.Mutex

	c *telemetry.Component
}

type ffCmd struct {
	clearRecords  bool
	serverVersion uint64
	records       []*Record
}

func newFastForwardHandler(ctx context.Context, tracerProvider oteltrace.TracerProvider, id string, handler SyncerHandler) SyncerHandler {
	ff := &fastForwardHandler{
		id:      id,
		handler: handler,
		pending: make(chan ffCmd, 1),
		c:       telemetry.NewComponent(tracerProvider, zerolog.DebugLevel, "databroker.fastforward", attribute.String(metrics.SyncerIDLabel, id)),
	}
	go ff.run(ctx)
	return ff
}

func (ff *fastForwardHandler) run(ctx context.Context) {
	ctx, active := ff.c.Active(ctx, "active")
	defer active.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-ff.pending:
			ff.processCmd(ctx, cmd)
		}
	}
}

func (ff *fastForwardHandler) processCmd(ctx context.Context, cmd ffCmd) {
	if cmd.clearRecords {
		ctx, op := ff.c.Start(ctx, "ClearRecords")
		ff.handler.ClearRecords(ctx)
		op.Complete()
		return
	}

	ctx, op := ff.c.Start(ctx, "UpdateRecords", attribute.Int("records", len(cmd.records)))
	ff.handler.UpdateRecords(ctx, cmd.serverVersion, cmd.records)
	op.Complete()
}

func (ff *fastForwardHandler) GetDataBrokerServiceClient() DataBrokerServiceClient {
	return ff.handler.GetDataBrokerServiceClient()
}

func (ff *fastForwardHandler) ClearRecords(ctx context.Context) {
	ff.mu.Lock()
	defer ff.mu.Unlock()

	var cmd ffCmd
	select {
	case <-ctx.Done():
		return
	case cmd = <-ff.pending:
	default:
	}
	cmd.clearRecords = true
	cmd.records = nil

	_, op := ff.c.Start(ctx, "Enqueue/ClearRecords")
	select {
	case <-ctx.Done():
		_ = op.Failure(errors.New("cancelled"))
	case ff.pending <- cmd:
		op.Complete()
	}
}

func (ff *fastForwardHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*Record) {
	ctx, op := ff.c.Start(ctx, "Enqueue/UpdateRecords")
	defer op.Complete()

	ff.mu.Lock()
	defer ff.mu.Unlock()

	var cmd ffCmd
	select {
	case <-ctx.Done():
		_ = op.Failure(errors.New("cancelled"))
	case cmd = <-ff.pending:
	default:
	}

	records = append(cmd.records, records...)
	// reverse, so that when we get the unique records, the newest take precedence
	slices.Reverse(records)
	cnt := len(records)
	records = slices.UniqueBy(records, func(record *Record) [2]string {
		return [2]string{record.GetType(), record.GetId()}
	})
	dropped := cnt - len(records)
	if dropped > 0 {
		log.Ctx(ctx).Info().Str("syncer-id", ff.id).Msgf("databroker: fast-forwarded %d records", dropped)
		internalmetrics.Int64Counter(metrics.DatabrokerFastForwardDropped).Add(
			ctx,
			int64(dropped),
			otelmetric.WithAttributes(
				attribute.String(metrics.SyncerIDLabel, ff.id),
			),
		)
	}
	// reverse back so they appear in the order they were delivered
	slices.Reverse(records)

	cmd.clearRecords = false
	cmd.serverVersion = serverVersion
	cmd.records = records

	select {
	case <-ctx.Done():
		_ = op.Failure(errors.New("cancelled"))
	case ff.pending <- cmd:
		op.Complete()
	}
}
