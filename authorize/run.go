package authorize

import (
	"context"
	"io"
	"time"

	"github.com/pomerium/pomerium/internal/telemetry/trace"

	backoff "github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
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
		ctx, span := trace.StartSpan(ctx, "authorize.dataBrokerClient.Sync")
		defer span.End()
		stream, err := a.dataBrokerClient.SyncTypes(ctx, new(emptypb.Empty))
		if err != nil {
			return err
		}

		for {
			res, err := stream.Recv()
			if err == io.EOF {
				return nil
			} else if err != nil {
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
	var serverVersion, recordVersion string

	log.Info().Str("type_url", typeURL).Msg("starting data initial load")
	ctx, span := trace.StartSpan(ctx, "authorize.dataBrokerClient.GetAll")
	backoff := backoff.NewExponentialBackOff()
	for {
		res, err := a.dataBrokerClient.GetAll(ctx, &databroker.GetAllRequest{
			Type: typeURL,
		})
		if err != nil {
			log.Warn().Err(err).Str("type_url", typeURL).Msg("error getting data")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff.NextBackOff()):
			}
			continue
		}

		serverVersion = res.GetServerVersion()
		if typeURL == sessionTypeURL {
			a.dataBrokerDataLock.Lock()
			a.dataBrokerSessionServerVersion = serverVersion
			a.dataBrokerDataLock.Unlock()
		}
		recordVersion = res.GetRecordVersion()

		for _, record := range res.GetRecords() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case updateRecord <- record:
			}
		}

		break
	}
	span.End()

	log.Info().Str("type_url", typeURL).Msg("starting data syncer")
	return tryForever(ctx, func(backoff interface{ Reset() }) error {
		ctx, span := trace.StartSpan(ctx, "authorize.dataBrokerClient.Sync")
		defer span.End()
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
			if err == io.EOF {
				return nil
			} else if err != nil {
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

		a.store.UpdateRecord(record)

		a.dataBrokerDataLock.Lock()
		a.dataBrokerData.Update(record)
		a.dataBrokerDataLock.Unlock()
	}
}

func tryForever(ctx context.Context, callback func(onSuccess interface{ Reset() }) error) error {
	backoff := backoff.NewExponentialBackOff()
	for {
		err := callback(backoff)
		if err != nil {
			log.Warn().Err(err).Msg("sync error")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff.NextBackOff()):
		}
	}
}
