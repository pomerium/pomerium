package cluster

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/pomerium/pomerium/internal/zero/apierror"
	"github.com/pomerium/pomerium/internal/zero/token"
)

// NewTokenFetcher creates a new authorization token fetcher
func NewTokenFetcher(endpoint string, opts ...ClientOption) (token.Fetcher, error) {
	client, err := NewClientWithResponses(endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}

	return func(ctx context.Context, refreshToken string) (*token.Token, error) {
		now := time.Now()

		resp, err := apierror.CheckResponse[ExchangeTokenResponse](client.ExchangeClusterIdentityTokenWithResponse(ctx, ExchangeTokenRequest{
			RefreshToken: refreshToken,
		}))
		if err != nil {
			return nil, fmt.Errorf("error exchanging token: %w", err)
		}

		expiresSeconds, err := strconv.ParseInt(resp.ExpiresInSeconds, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("error parsing expires in: %w", err)
		}

		return &token.Token{
			Bearer:  resp.IdToken,
			Expires: now.Add(time.Duration(expiresSeconds) * time.Second),
		}, nil
	}, nil
}
