package bootstrap

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/config"
	cluster_api "github.com/pomerium/zero-sdk/cluster"
)

// LoadBootstrapConfigFromAPI loads the bootstrap configuration from the cluster API.
func LoadBootstrapConfigFromAPI(
	ctx context.Context,
	dst *config.Options,
	client cluster_api.ClientWithResponsesInterface,
) error {
	resp, err := client.GetClusterBootstrapConfigWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("unexpected response: %d/%v", resp.StatusCode(), resp.Status())
	}

	v := cluster_api.BootstrapConfig(*resp.JSON200)

	if v.DatabrokerStorageConnection != nil {
		dst.DataBrokerStorageType = "postgres"
		dst.DataBrokerStorageConnectionString = *v.DatabrokerStorageConnection
	}

	return nil
}
