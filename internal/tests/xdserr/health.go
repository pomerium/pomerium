package xdserr

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/pkg/grpc/config"
)

// WaitForHealthy waits until all routes are up
func WaitForHealthy(ctx context.Context, client *http.Client, routes []*config.Route) error {
	healthy := 0
	for healthy != len(routes) && ctx.Err() == nil {
		healthy = 0
		for _, r := range routes {
			if err := checkHealth(ctx, client, r.From); err != nil {
				continue
			}
			healthy++
		}
	}
	return context.Cause(ctx)
}

func checkHealth(ctx context.Context, client *http.Client, addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}
	req := http.Request{
		Method: http.MethodGet,
		URL:    u,
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err = io.ReadAll(resp.Body); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}
