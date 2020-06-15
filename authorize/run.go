package authorize

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
	"gopkg.in/tomb.v2"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/log"
)

// Run runs the authorize server.
func (a *Authorize) Run(ctx context.Context) error {
	t, ctx := tomb.WithContext(ctx)

	updateTypes := make(chan []string)
	t.Go(func() error {
		return a.runTypesSyncer(ctx, updateTypes)
	})

	updateRecord := make(chan *databroker.Record)
	t.Go(func() error {
		return a.runDataSyncer(ctx, updateTypes, updateRecord)
	})

	t.Go(func() error {
		return a.runDataUpdater(ctx, updateRecord)
	})

	return t.Wait()
}

func (a *Authorize) runTypesSyncer(ctx context.Context, updateTypes chan<- []string) error {
	log.Info().Msg("starting type sync")

	client, err := a.dataBrokerClient.SyncTypes(ctx, new(emptypb.Empty))
	if err != nil {
		return err
	}
	for {
		res, err := client.Recv()
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case updateTypes <- res.GetTypes():
		}
	}
}

func (a *Authorize) runDataSyncer(ctx context.Context, updateTypes <-chan []string, updateRecord chan<- *databroker.Record) error {
	t, ctx := tomb.WithContext(ctx)
	t.Go(func() error {
		seen := map[string]struct{}{}
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case types := <-updateTypes:
				for _, dataType := range types {
					dataType := dataType
					if _, ok := seen[dataType]; !ok {
						t.Go(func() error {
							return a.runDataTypeSyncer(ctx, dataType, updateRecord)
						})
						seen[dataType] = struct{}{}
					}
				}
			}
		}
	})
	return t.Wait()
}

func (a *Authorize) runDataTypeSyncer(ctx context.Context, dataType string, updateRecord chan<- *databroker.Record) error {
	log.Info().Str("type", dataType).Msg("starting data syncer")
	client, err := a.dataBrokerClient.Sync(ctx, &databroker.SyncRequest{
		ServerVersion: "",
		RecordVersion: "",
		Type:          dataType,
	})
	if err != nil {
		return err
	}

	for {
		res, err := client.Recv()
		if err != nil {
			return err
		}
		for _, record := range res.GetRecords() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case updateRecord <- record:
			}
		}
	}
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
