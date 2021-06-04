package databroker

import (
	"context"
	"fmt"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/contextkeys"
	"github.com/pomerium/pomerium/internal/log"
)

type syncerConfig struct {
	typeURL string
}

// A SyncerOption customizes the syncer configuration.
type SyncerOption func(cfg *syncerConfig)

func getSyncerConfig(options ...SyncerOption) *syncerConfig {
	cfg := new(syncerConfig)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// WithTypeURL restricts the sync'd results to the given type.
func WithTypeURL(typeURL string) SyncerOption {
	return func(cfg *syncerConfig) {
		cfg.typeURL = typeURL
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
	cfg     *syncerConfig
	handler SyncerHandler
	backoff *backoff.ExponentialBackOff

	recordVersion uint64
	serverVersion uint64

	closeCtx       context.Context
	closeCtxCancel func()

	id string
}

// NewSyncer creates a new Syncer.
func NewSyncer(id string, handler SyncerHandler, options ...SyncerOption) *Syncer {
	closeCtx, closeCtxCancel := context.WithCancel(context.Background())

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	return &Syncer{
		cfg:     getSyncerConfig(options...),
		handler: handler,
		backoff: bo,

		closeCtx:       closeCtx,
		closeCtxCancel: closeCtxCancel,

		id: id,
	}
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

	ctx = syncer.logCtx(ctx)
	for {
		var err error
		if syncer.serverVersion == 0 {
			err = syncer.init(ctx)
		} else {
			err = syncer.sync(ctx)
		}

		if err != nil {
			log.Error(ctx).Err(err).Msg("sync")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(syncer.backoff.NextBackOff()):
			}
		}
	}
}

func (syncer *Syncer) init(ctx context.Context) error {
	log.Info(ctx).Msg("initial sync")
	records, recordVersion, serverVersion, err := InitialSync(ctx, syncer.handler.GetDataBrokerServiceClient(), &SyncLatestRequest{
		Type: syncer.cfg.typeURL,
	})
	if err != nil {
		log.Error(ctx).Err(err).Msg("error during initial sync")
		return err
	}
	syncer.backoff.Reset()

	// reset the records as we have to sync latest
	syncer.handler.ClearRecords(ctx)

	syncer.recordVersion = recordVersion
	syncer.serverVersion = serverVersion
	syncer.handler.UpdateRecords(ctx, serverVersion, records)

	return nil
}

func (syncer *Syncer) sync(ctx context.Context) error {
	stream, err := syncer.handler.GetDataBrokerServiceClient().Sync(ctx, &SyncRequest{
		ServerVersion: syncer.serverVersion,
		RecordVersion: syncer.recordVersion,
	})
	if err != nil {
		log.Error(ctx).Err(err).Msg("error during sync")
		return err
	}

	log.Info(ctx).Msg("listening for updates")

	for {
		res, err := stream.Recv()
		if status.Code(err) == codes.Aborted {
			log.Error(ctx).Err(err).Msg("aborted sync due to mismatched server version")
			// server version changed, so re-init
			syncer.serverVersion = 0
			return nil
		} else if err != nil {
			return err
		}

		rec := res.GetRecord()
		log.Debug(logCtxRec(ctx, rec)).Msg("syncer got record")

		if syncer.recordVersion != res.GetRecord().GetVersion()-1 {
			log.Error(logCtxRec(ctx, rec)).Err(err).
				Msg("aborted sync due to missing record")
			syncer.serverVersion = 0
			return fmt.Errorf("missing record version")
		}
		syncer.recordVersion = res.GetRecord().GetVersion()
		if syncer.cfg.typeURL == "" || syncer.cfg.typeURL == res.GetRecord().GetType() {
			ctx := logCtxRec(ctx, rec)
			log.Debug(ctx).Msg("update records")
			syncer.handler.UpdateRecords(
				context.WithValue(ctx, contextkeys.UpdateRecordsVersion, rec.GetVersion()),
				syncer.serverVersion, []*Record{rec})
		}
	}
}

// logCtxRecRec adds log params to context related to particular record
func logCtxRec(ctx context.Context, rec *Record) context.Context {
	return log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("record_type", rec.GetType()).
			Str("record_id", rec.GetId()).
			Uint64("record_version", rec.GetVersion())
	})
}

func (syncer *Syncer) logCtx(ctx context.Context) context.Context {
	return log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("syncer_id", syncer.id).
			Str("syncer_type", syncer.cfg.typeURL)
	})
}
