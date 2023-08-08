package bootstrap

import (
	"context"
	"fmt"

	cluster_api "github.com/pomerium/zero-sdk/cluster"
)

// LoadBootstrapConfigFromAPI loads the bootstrap configuration from the cluster API.
func LoadBootstrapConfigFromAPI(
	ctx context.Context,
	client cluster_api.ClientWithResponsesInterface,
) (*cluster_api.BootstrapConfig, error) {
	resp, err := client.GetClusterBootstrapConfigWithResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected response: %d/%v", resp.StatusCode(), resp.Status())
	}

	return resp.JSON200, nil
}
