package authorize

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/cenkalti/backoff"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/log"
)

// Run runs the authorize server.
func (a *Authorize) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	updateTypes := make(chan []string)
	eg.Go(func() error {
		return a.runTypesSyncer(ctx, updateTypes)
	})

	updateRecord := make(chan *databroker.Record)
	eg.Go(func() error {
		return a.runDataSyncer(ctx, updateTypes, updateRecord)
	})

	eg.Go(func() error {
		return a.runDataUpdater(ctx, updateRecord)
	})

	return eg.Wait()
}

func (a *Authorize) runTypesSyncer(ctx context.Context, updateTypes chan<- []string) error {
	log.Info().Msg("starting type sync")
	return tryForever(ctx, func(backoff interface{ Reset() }) error {
		stream, err := a.dataBrokerClient.SyncTypes(ctx, new(emptypb.Empty))
		if err != nil {
			return err
		}

		for {
			res, err := stream.Recv()
			if err != nil {
				return err
			}

			backoff.Reset()

			select {
			case <-stream.Context().Done():
				return stream.Context().Err()
			case updateTypes <- res.GetTypes():
			}
		}
	})
}

func (a *Authorize) runDataSyncer(ctx context.Context, updateTypes <-chan []string, updateRecord chan<- *databroker.Record) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		seen := map[string]struct{}{}
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case types := <-updateTypes:
				for _, dataType := range types {
					dataType := dataType
					if _, ok := seen[dataType]; !ok {
						eg.Go(func() error {
							return a.runDataTypeSyncer(ctx, dataType, updateRecord)
						})
						seen[dataType] = struct{}{}
					}
				}
			}
		}
	})
	return eg.Wait()
}

func (a *Authorize) runDataTypeSyncer(ctx context.Context, typeURL string, updateRecord chan<- *databroker.Record) error {
	log.Info().Str("type_url", typeURL).Msg("starting data syncer")
	var serverVersion, recordVersion string
	return tryForever(ctx, func(backoff interface{ Reset() }) error {
		stream, err := a.dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
			ServerVersion: serverVersion,
			RecordVersion: recordVersion,
			Type:          typeURL,
		})
		if err != nil {
			return err
		}

		for {
			res, err := stream.Recv()
			if err != nil {
				return err
			}

			backoff.Reset()
			serverVersion = res.GetServerVersion()
			for _, record := range res.GetRecords() {
				if record.GetVersion() > recordVersion {
					recordVersion = record.GetVersion()
				}
			}

			for _, record := range res.GetRecords() {
				select {
				case <-stream.Context().Done():
					return stream.Context().Err()
				case updateRecord <- record:
				}
			}
		}
	})
}

func (a *Authorize) runDataUpdater(ctx context.Context, updateRecord <-chan *databroker.Record) error {
	log.Info().Msg("starting data updater")
	for {
		var record *databroker.Record

		select {
		case <-ctx.Done():
			return ctx.Err()
		case record = <-updateRecord:
		}

		a.dataBrokerDataLock.Lock()
		a.dataBrokerData.Update(record)
		a.dataBrokerDataLock.Unlock()
	}
}

func tryForever(ctx context.Context, callback func(onSuccess interface{ Reset() }) error) error {
	backoff := backoff.NewExponentialBackOff()
	for {
		err := callback(backoff)
		log.Warn().Err(err).Msg("sync error")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff.NextBackOff()):
		}
	}
}
