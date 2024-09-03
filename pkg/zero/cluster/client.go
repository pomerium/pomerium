// Package cluster is an API client for the cluster service
package cluster

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pomerium/pomerium/internal/version"
)

const (
	defaultMinTokenTTL = time.Minute * 5
)

var userAgent = version.UserAgent()

type client struct {
	tokenProvider TokenCache
	httpClient    *http.Client
	minTokenTTL   time.Duration
}

// TokenCache interface for fetching and caching tokens
type TokenCache interface {
	// GetToken returns a token that is expected to be valid for at least minTTL duration
	GetToken(ctx context.Context, minTTL time.Duration) (string, error)
	// Reset resets the token cache
	Reset()
}

// NewAuthorizedClient creates a new HTTP client that will automatically add an authorization header
func NewAuthorizedClient(
	endpoint string,
	tokenProvider TokenCache,
	httpClient *http.Client,
) (ClientWithResponsesInterface, error) {
	c := &client{
		minTokenTTL: defaultMinTokenTTL,
		httpClient:  httpClient,
	}

	c.tokenProvider = tokenProvider

	return NewClientWithResponses(endpoint, WithHTTPClient(c))
}

func (c *client) Do(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	token, err := c.tokenProvider.GetToken(ctx, c.minTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("error getting token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		c.tokenProvider.Reset()
	}

	return resp, nil
}
