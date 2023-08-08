package controller

import (
	"context"
	"fmt"
	"net/http"

	cluster_api "github.com/pomerium/zero-sdk/cluster"
	connect_api "github.com/pomerium/zero-sdk/connect"
	connect_mux "github.com/pomerium/zero-sdk/connect-mux"
	token_api "github.com/pomerium/zero-sdk/token"
)

func (c *controller) InitAPI(ctx context.Context) error {
	fetcher, err := cluster_api.NewTokenFetcher(c.cfg.clusterAPIEndpoint)
	if err != nil {
		return fmt.Errorf("error creating token fetcher: %w", err)
	}

	tokenCache := token_api.NewCache(fetcher, c.cfg.apiToken)

	clusterClient, err := cluster_api.NewAuthorizedClient(c.cfg.clusterAPIEndpoint, tokenCache.GetToken, http.DefaultClient)
	if err != nil {
		return fmt.Errorf("error creating cluster client: %w", err)
	}

	connectClient, err := connect_api.NewAuthorizedConnectClient(ctx, c.cfg.connectAPIEndpoint, tokenCache.GetToken)
	if err != nil {
		return fmt.Errorf("error creating connect client: %w", err)
	}

	c.connectMux = connect_mux.Start(ctx, connectClient)
	c.clusterClient = clusterClient

	return nil
}
