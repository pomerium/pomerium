package databroker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A SyncerHandler receives sync events from the Syncer.
type SyncerHandler interface {
	GetDataBrokerServiceClient() DataBrokerServiceClient
	ClearRecords(ctx context.Context)
	UpdateRecords(ctx context.Context, records []*Record)
}

// A Syncer is a helper type for working with Sync and SyncLatest. It will make a call to
// SyncLatest to retrieve the latest version of the data, then begin syncing with a call
// to Sync. If the server version changes `ClearRecords` will be called and the process
// will start over.
type Syncer struct {
	handler SyncerHandler
	backoff *backoff.ExponentialBackOff

	closeOnce sync.Once
	closed    chan struct{}
}

// NewSyncer creates a new Syncer.
func NewSyncer(handler SyncerHandler) *Syncer {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	return &Syncer{
		handler: handler,
		backoff: bo,

		closed: make(chan struct{}),
	}
}

// Close closes the Syncer.
func (syncer *Syncer) Close() error {
	syncer.closeOnce.Do(func() {
		close(syncer.closed)
	})
	return nil
}

// Run runs the Syncer.
func (syncer *Syncer) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		<-syncer.closed
		cancel()
	}()

	var recordVersion, serverVersion uint64
	for {
		var err error
		if serverVersion == 0 {
			err = syncer.init(ctx, &recordVersion, &serverVersion)
		} else {
			err = syncer.sync(ctx, &recordVersion, &serverVersion)
		}

		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(syncer.backoff.NextBackOff()):
			case <-syncer.closed:
				return context.Canceled
			}
		}
	}
}

func (syncer *Syncer) init(ctx context.Context, recordVersion, serverVersion *uint64) error {
	records, v, err := InitialSync(ctx, syncer.handler.GetDataBrokerServiceClient())
	if err != nil {
		return err
	}
	syncer.backoff.Reset()

	// reset the records as we have to sync latest
	syncer.handler.ClearRecords(ctx)

	*serverVersion = v
	for _, record := range records {
		if record.GetVersion() > *recordVersion {
			*recordVersion = record.GetVersion()
		}
	}
	syncer.handler.UpdateRecords(ctx, records)

	return nil
}

func (syncer *Syncer) sync(ctx context.Context, recordVersion, serverVersion *uint64) error {
	stream, err := syncer.handler.GetDataBrokerServiceClient().Sync(ctx, &SyncRequest{
		ServerVersion: *serverVersion,
		RecordVersion: *recordVersion,
	})
	if err != nil {
		return err
	}

	for {
		res, err := stream.Recv()
		if status.Code(err) == codes.Aborted {
			// server version changed, so re-init
			*serverVersion = 0
			return nil
		} else if err != nil {
			return err
		}

		if *recordVersion != res.GetRecord().GetVersion()-1 {
			*serverVersion = 0
			return fmt.Errorf("missing record version")
		}
		*recordVersion = res.GetRecord().GetVersion()
		syncer.handler.UpdateRecords(ctx, []*Record{res.GetRecord()})
	}
}
