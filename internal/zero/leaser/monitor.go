package leaser

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

const typeStr = "pomerium.io/zero/leaser"

// databrokerChangeMonitor runs infinite sync loop to see if there is any change in databroker
// it doesn't really syncs anything, just checks if the underlying databroker has changed
func databrokerChangeMonitor(ctx context.Context, client databroker.DataBrokerServiceClient) error {
	_, recordVersion, serverVersion, err := databroker.InitialSync(ctx, client, &databroker.SyncLatestRequest{
		Type: typeStr,
	})
	if err != nil {
		return fmt.Errorf("error during initial sync: %w", err)
	}

	stream, err := client.Sync(ctx, &databroker.SyncRequest{
		Type:          typeStr,
		ServerVersion: serverVersion,
		RecordVersion: recordVersion,
	})
	if err != nil {
		return fmt.Errorf("error calling sync: %w", err)
	}

	for {
		_, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("error receiving record: %w", err)
		}
	}
}
