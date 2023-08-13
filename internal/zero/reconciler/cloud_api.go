package reconciler

import (
	"context"
	"fmt"
)

// GetBundles returns the list of bundles that have to be present in the cluster.
func (c *service) RefreshBundleList(ctx context.Context) error {
	resp, err := c.config.api.GetClusterResourceBundles(ctx)
	if err != nil {
		return fmt.Errorf("get bundles: %w", err)
	}

	ids := make([]string, 0, len(resp.Bundles))
	for _, v := range resp.Bundles {
		ids = append(ids, v.Id)
	}

	c.bundles.Set(ids)
	return nil
}
