package authorize

import (
	"context"
	"io"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Run runs the authorize server.
func (a *Authorize) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	updateTypes := make(chan []string)
	eg.Go(func() error {
		return a.runTypesSyncer(ctx, updateTypes)
	})

	eg.Go(func() error {
		return a.runDataSyncer(ctx, updateTypes)
	})

	return eg.Wait()
}

// WaitForInitialSync waits for the initial sync to complete.
func (a *Authorize) WaitForInitialSync(ctx context.Context) error {
	for typeURL, ch := range a.dataBrokerInitialSync {
		log.Info().Str("type_url", typeURL).Msg("waiting for initial sync")
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
		log.Info().Str("type_url", typeURL).Msg("initial sync complete")
	}
	return nil
}

func (a *Authorize) runTypesSyncer(ctx context.Context, updateTypes chan<- []string) error {
	log.Info().Msg("starting type sync")
	return tryForever(ctx, func(backoff interface{ Reset() }) error {
		ctx, span := trace.StartSpan(ctx, "authorize.dataBrokerClient.Sync")
		defer span.End()
		stream, err := a.state.Load().dataBrokerClient.SyncTypes(ctx, new(emptypb.Empty))
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

func (a *Authorize) runDataSyncer(ctx context.Context, updateTypes <-chan []string) error {
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
							return a.runDataTypeSyncer(ctx, dataType)
						})
						seen[dataType] = struct{}{}
					}
				}
			}
		}
	})
	return eg.Wait()
}

func (a *Authorize) runDataTypeSyncer(ctx context.Context, typeURL string) error {
	var serverVersion, recordVersion string

	log.Info().Str("type_url", typeURL).Msg("starting data initial load")
	ctx, span := trace.StartSpan(ctx, "authorize.dataBrokerClient.InitialSync")
	backoff := backoff.NewExponentialBackOff()
	backoff.MaxElapsedTime = 0
	for {
		res, err := databroker.InitialSync(ctx, a.state.Load().dataBrokerClient, &databroker.SyncRequest{
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

		for _, record := range res.GetRecords() {
			a.store.UpdateRecord(record)
			recordVersion = record.GetVersion()
		}

		break
	}
	span.End()

	if ch, ok := a.dataBrokerInitialSync[typeURL]; ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}

	log.Info().Str("type_url", typeURL).Msg("starting data syncer")
	return tryForever(ctx, func(backoff interface{ Reset() }) error {
		ctx, span := trace.StartSpan(ctx, "authorize.dataBrokerClient.Sync")
		defer span.End()
		stream, err := a.state.Load().dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
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
			if res.GetServerVersion() != serverVersion {
				log.Info().
					Str("old_version", serverVersion).
					Str("new_version", res.GetServerVersion()).
					Str("type_url", typeURL).
					Msg("detected new server version, clearing data")
				serverVersion = res.GetServerVersion()
				recordVersion = ""
				a.store.ClearRecords(typeURL)
			}
			for _, record := range res.GetRecords() {
				if record.GetVersion() > recordVersion {
					recordVersion = record.GetVersion()
				}
			}

			for _, record := range res.GetRecords() {
				a.store.UpdateRecord(record)
			}
		}
	})
}

func tryForever(ctx context.Context, callback func(onSuccess interface{ Reset() }) error) error {
	backoff := backoff.NewExponentialBackOff()
	backoff.MaxElapsedTime = 0
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
