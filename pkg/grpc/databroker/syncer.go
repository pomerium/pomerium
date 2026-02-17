package databroker

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	oteltrace "go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/contextkeys"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/metrics"
)

type syncerConfig struct {
	tracerProvider  oteltrace.TracerProvider
	typeURL         string
	withFastForward bool
	metrics         *SyncerMetrics
	backoff.BackOff
}

// A SyncerOption customizes the syncer configuration.
type SyncerOption func(cfg *syncerConfig)

func getSyncerConfig(options ...SyncerOption) *syncerConfig {
	cfg := new(syncerConfig)
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	cfg.BackOff = bo
	WithSyncerTracerProvider(nooptrace.NewTracerProvider())(cfg)
	m, _ := NewSyncerMetrics(otel.Meter("syncer"))
	WithSyncerMetrics(m)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

func WithSyncerMetrics(m *SyncerMetrics) SyncerOption {
	return func(cfg *syncerConfig) {
		cfg.metrics = m
	}
}

// WithSyncerTracerProvider sets the tracer provider for the syncer.
func WithSyncerTracerProvider(tracerProvider oteltrace.TracerProvider) SyncerOption {
	return func(cfg *syncerConfig) {
		cfg.tracerProvider = tracerProvider
	}
}

// WithTypeURL restricts the sync'd results to the given type.
func WithTypeURL(typeURL string) SyncerOption {
	return func(cfg *syncerConfig) {
		cfg.typeURL = typeURL
	}
}

// WithFastForward in case updates are coming faster then Update can process them,
// will skip older records to maintain an update rate.
// Use for entries that represent a full state snapshot i.e. Config
func WithFastForward() SyncerOption {
	return func(cfg *syncerConfig) {
		cfg.withFastForward = true
	}
}

func WithBackOff(bo backoff.BackOff) SyncerOption {
	return func(cfg *syncerConfig) {
		cfg.BackOff = bo
	}
}

// A SyncerHandler receives sync events from the Syncer.
type SyncerHandler interface {
	GetDataBrokerServiceClient() DataBrokerServiceClient
	ClearRecords(ctx context.Context)
	UpdateRecords(ctx context.Context, serverVersion uint64, records []*Record)
}

// A Syncer is a helper type for working with Sync and SyncLatest. It will make a call to
// SyncLatest to retrieve the latest version of the data, then begin syncing with a call
// to Sync. If the server version changes `ClearRecords` will be called and the process
// will start over.
type Syncer struct {
	cfg           *syncerConfig
	handler       SyncerHandler
	recordVersion uint64
	serverVersion uint64

	closeCtx       context.Context
	closeCtxCancel func()
	commonAttrs    []attribute.KeyValue

	id string
}

var DebugUseFasterBackoff atomic.Bool

// NewSyncer creates a new Syncer.
func NewSyncer(ctx context.Context, id string, handler SyncerHandler, options ...SyncerOption) *Syncer {
	closeCtx, closeCtxCancel := context.WithCancel(context.WithoutCancel(ctx))

	cfg := getSyncerConfig(options...)

	if DebugUseFasterBackoff.Load() {
		bo := backoff.NewExponentialBackOff(
			backoff.WithInitialInterval(10*time.Millisecond),
			backoff.WithMultiplier(1.0),
			backoff.WithMaxElapsedTime(100*time.Millisecond),
		)
		bo.MaxElapsedTime = 0
		cfg.BackOff = bo
	}

	s := &Syncer{
		cfg:     cfg,
		handler: handler,

		closeCtx:       closeCtx,
		closeCtxCancel: closeCtxCancel,

		id: id,
	}
	attrTypeURL := "all"
	if s.cfg.typeURL != "" {
		attrTypeURL = s.cfg.typeURL
	}
	s.commonAttrs = []attribute.KeyValue{
		attribute.String("record-type", grpcutil.WithoutTypeURLPrefix(attrTypeURL)),
		attribute.String("syncer-id", s.id),
	}
	if s.cfg.withFastForward {
		s.handler = newFastForwardHandler(closeCtx, s.cfg.tracerProvider, id, handler)
	}
	return s
}

// Close closes the Syncer.
func (syncer *Syncer) Close() error {
	syncer.closeCtxCancel()
	return nil
}

// Run runs the Syncer.
func (syncer *Syncer) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		<-syncer.closeCtx.Done()
		cancel()
	}()

	for {
		var err error
		if syncer.serverVersion == 0 {
			syncer.recordOverallSyncState(ctx, SyncPending)
			err = syncer.init(ctx)
		} else {
			syncer.recordOverallSyncState(ctx, SyncActive)
			err = syncer.sync(ctx)
		}
		syncer.recordOverallSyncState(ctx, SyncInactive)
		if err != nil {
			log.Ctx(ctx).Error().
				Str("syncer-id", syncer.id).
				Str("syncer-type", syncer.cfg.typeURL).
				Err(err).
				Msg("sync")
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-time.After(syncer.cfg.BackOff.NextBackOff()):
			}
		}
	}
}

func (syncer *Syncer) init(ctx context.Context) error {
	log.Ctx(ctx).Debug().
		Str("syncer-id", syncer.id).
		Str("syncer-type", syncer.cfg.typeURL).
		Msg("initial sync")
	records, _, recordVersion, serverVersion, err := InitialSync(ctx, syncer.handler.GetDataBrokerServiceClient(), &SyncLatestRequest{
		Type: syncer.cfg.typeURL,
	})
	syncer.incSyncLatest(ctx, err)
	if err != nil {
		if status.Code(err) == codes.Canceled && ctx.Err() != nil {
			err = fmt.Errorf("%w: %w", err, context.Cause(ctx))
		}
		return fmt.Errorf("error during initial sync: %w", err)
	}
	syncer.recordVersion = recordVersion
	syncer.serverVersion = serverVersion
	syncer.cfg.BackOff.Reset()
	syncer.recordLatestVersions(ctx)
	// reset the records as we have to sync latest records to handlers
	startClear := time.Now()
	syncer.handler.ClearRecords(ctx)
	syncer.onClearRecords(ctx, startClear)
	startUpdateRecs := time.Now()
	syncer.handler.UpdateRecords(ctx, serverVersion, records)
	syncer.onUpdateRecords(ctx, startUpdateRecs, len(records))
	return nil
}

func (syncer *Syncer) resetServerVersion(ctx context.Context) {
	syncer.serverVersion = 0
	syncer.cfg.metrics.ServerVersion.Record(
		ctx, 0, metric.WithAttributeSet(
			attribute.NewSet(syncer.commonAttrs...),
		),
	)
}

func (syncer *Syncer) sync(ctx context.Context) error {
	stream, err := syncer.handler.GetDataBrokerServiceClient().Sync(ctx, &SyncRequest{
		ServerVersion: syncer.serverVersion,
		RecordVersion: syncer.recordVersion,
		Type:          syncer.cfg.typeURL,
	})
	syncer.incSync(ctx, err)
	if err != nil {
		return fmt.Errorf("error calling sync: %w", err)
	}

	log.Ctx(ctx).Debug().
		Str("syncer-id", syncer.id).
		Str("syncer-type", syncer.cfg.typeURL).
		Msg("listening for updates")

	for {
		res, err := stream.Recv()
		syncer.incSync(ctx, err)
		if status.Code(err) == codes.Aborted {
			log.Ctx(ctx).Error().Err(err).
				Str("syncer-id", syncer.id).
				Str("syncer-type", syncer.cfg.typeURL).
				Msg("aborted sync due to mismatched versions")
			// server version may: have changed, so re-init
			syncer.resetServerVersion(ctx)
			return nil
		} else if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("%w: %w", err, context.Cause(ctx))
			}
			return fmt.Errorf("error receiving sync record: %w", err)
		}
		switch res := res.Response.(type) {
		case *SyncResponse_Record:
			syncer.recordVersion = res.Record.GetVersion()
			log.Ctx(logCtxRec(ctx, res.Record)).Debug().
				Str("syncer-id", syncer.id).
				Str("syncer-type", syncer.cfg.typeURL).
				Msg("syncer got record")

			if syncer.cfg.typeURL == "" || syncer.cfg.typeURL == res.Record.GetType() {
				syncer.recordLatestVersions(ctx)
				start := time.Now()
				syncer.handler.UpdateRecords(
					context.WithValue(ctx, contextkeys.UpdateRecordsVersion, res.Record.GetVersion()),
					syncer.serverVersion, []*Record{res.Record})
				syncer.onUpdateRecords(ctx, start, 1)
			}
		}
	}
}

func (syncer *Syncer) recordOverallSyncState(ctx context.Context, val overallSyncState) {
	syncer.cfg.metrics.SyncerActive.Record(ctx, int64(val), metric.WithAttributeSet(
		attribute.NewSet(syncer.commonAttrs...),
	))
}

func (syncer *Syncer) incSyncLatest(ctx context.Context, err error) {
	as := attribute.NewSet(syncer.commonAttrs...)
	syncer.cfg.metrics.SyncLatestTotal.Add(ctx, 1, metric.WithAttributeSet(as))
	if err != nil {
		syncer.cfg.metrics.SyncLatestFailures.Add(ctx, 1, metric.WithAttributeSet(as))
	}
}

func (syncer *Syncer) incSync(ctx context.Context, err error) {
	as := attribute.NewSet(syncer.commonAttrs...)
	syncer.cfg.metrics.SyncTotal.Add(ctx, 1, metric.WithAttributeSet(as))
	if err != nil {
		syncer.cfg.metrics.SyncFailures.Add(ctx, 1, metric.WithAttributeSet(as))
	}
}

func (syncer *Syncer) recordLatestVersions(ctx context.Context) {
	as := attribute.NewSet(syncer.commonAttrs...)
	syncer.cfg.metrics.ServerVersion.Record(ctx, int64(syncer.serverVersion), metric.WithAttributeSet(as))
	syncer.cfg.metrics.LatestRecordVersion.Record(ctx, int64(syncer.recordVersion), metric.WithAttributeSet(as))
}

func (syncer *Syncer) onClearRecords(ctx context.Context, startTime time.Time) {
	as := attribute.NewSet(syncer.commonAttrs...)
	syncer.cfg.metrics.ClearRecordsCount.Add(ctx, 1, metric.WithAttributeSet(as))
	syncer.cfg.metrics.ClearRecordsDuration.Record(ctx, time.Since(startTime).Seconds(), metric.WithAttributeSet(as))
}

func (syncer *Syncer) onUpdateRecords(ctx context.Context, startTime time.Time, numRecords int) {
	syncer.cfg.metrics.UpdateRecordsCount.Add(ctx, int64(numRecords), metric.WithAttributeSet(
		attribute.NewSet(syncer.commonAttrs...),
	))
	// we might be able to make smart use of double-histograms here
	syncer.cfg.metrics.UpdateRecordsDuration.Record(ctx, time.Since(startTime).Seconds(), metric.WithAttributeSet(
		attribute.NewSet(append(syncer.commonAttrs, attribute.String(
			"record-count", metrics.Bucketize(numRecords, 1000),
		))...),
	))
}

// logCtxRecRec adds log params to context related to particular record
func logCtxRec(ctx context.Context, rec *Record) context.Context {
	return log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("record-type", rec.GetType()).
			Str("record-id", rec.GetId()).
			Uint64("record-version", rec.GetVersion())
	})
}

type SyncerMetrics struct {
	SyncerActive        metric.Int64Gauge
	ServerVersion       metric.Int64Gauge
	LatestRecordVersion metric.Int64Gauge

	SyncTotal    metric.Int64Counter
	SyncFailures metric.Int64Counter

	SyncLatestTotal    metric.Int64Counter
	SyncLatestFailures metric.Int64Counter

	ClearRecordsCount    metric.Int64Counter
	ClearRecordsDuration metric.Float64Histogram

	UpdateRecordsCount    metric.Int64Counter
	UpdateRecordsDuration metric.Float64Histogram
}

func NewSyncerMetrics(m metric.Meter) (*SyncerMetrics, error) {
	syncerActive, err := m.Int64Gauge(
		"databroker.syncer.active",
		metric.WithDescription("if the current syncer is active or not"),
	)
	if err != nil {
		return nil, err
	}

	serverVersion, err := m.Int64Gauge(
		"databroker.syncer.server_version",
		metric.WithDescription("current server version from the databroker"),
	)
	if err != nil {
		return nil, err
	}

	latestRecordVersion, err := m.Int64Gauge(
		"databroker.syncer.latest_record_version",
		metric.WithDescription("latest record version from the databroker for this syncer type"),
	)
	if err != nil {
		return nil, err
	}

	syncTotal, err := m.Int64Counter(
		"databroker.syncer.sync.total",
		metric.WithDescription("total number of sync operations"),
	)
	if err != nil {
		return nil, err
	}

	syncFailures, err := m.Int64Counter(
		"databroker.syncer.sync.failures",
		metric.WithDescription("total number of failed sync operations"),
	)
	if err != nil {
		return nil, err
	}

	syncLatestTotal, err := m.Int64Counter(
		"databroker.syncer.sync_latest.total",
		metric.WithDescription("total number of sync latest operations"),
	)
	if err != nil {
		return nil, err
	}

	syncLatestFailures, err := m.Int64Counter(
		"databroker.syncer.sync_latest.failures",
		metric.WithDescription("total number of failed sync latest operations"),
	)
	if err != nil {
		return nil, err
	}

	clearRecordsCount, err := m.Int64Counter(
		"databroker.syncer.clear_records.total",
		metric.WithDescription("total number of clear records operations"),
	)
	if err != nil {
		return nil, err
	}

	clearRecordsDuration, err := m.Float64Histogram(
		"databroker.syncer.clear_records.duration",
		metric.WithUnit("s"),
		metric.WithDescription("duration of clear records operations"),
	)
	if err != nil {
		return nil, err
	}

	updateRecordsCount, err := m.Int64Counter(
		"databroker.syncer.update_records.total",
		metric.WithDescription("total number of records updated by the syncer handler"),
	)
	if err != nil {
		return nil, err
	}

	updateRecordsDuration, err := m.Float64Histogram(
		"databroker.syncer.update_records.duration",
		metric.WithUnit("s"),
		metric.WithDescription("duration of update records operations"),
	)
	if err != nil {
		return nil, err
	}

	return &SyncerMetrics{
		SyncerActive:          syncerActive,
		ServerVersion:         serverVersion,
		LatestRecordVersion:   latestRecordVersion,
		SyncTotal:             syncTotal,
		SyncFailures:          syncFailures,
		SyncLatestTotal:       syncLatestTotal,
		SyncLatestFailures:    syncLatestFailures,
		ClearRecordsCount:     clearRecordsCount,
		ClearRecordsDuration:  clearRecordsDuration,
		UpdateRecordsCount:    updateRecordsCount,
		UpdateRecordsDuration: updateRecordsDuration,
	}, nil
}

type overallSyncState int64

const (
	SyncInactive overallSyncState = iota
	SyncActive   overallSyncState = 1
	SyncPending  overallSyncState = 2
)
