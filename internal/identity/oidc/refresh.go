package oidc

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// Refresh requests a new oauth2.Token based on an existing Token and the
// provided Config. The existing Token must contain a refresh token.
func Refresh(ctx context.Context, cfg *oauth2.Config, t *oauth2.Token) (*oauth2.Token, error) {
	if t == nil || t.RefreshToken == "" {
		return nil, ErrMissingRefreshToken
	}

	// Note: the TokenSource returned by oauth2.Config has its own threshold
	// for determining when to attempt a refresh. In order to force a refresh
	// we can remove the current AccessToken.
	t = &oauth2.Token{
		TokenType:    t.TokenType,
		RefreshToken: t.RefreshToken,
	}
	newToken, err := cfg.TokenSource(ctx, t).Token()
	if err != nil {
		return nil, fmt.Errorf("identity/oidc: refresh failed: %w", err)
	}
	return newToken, nil
}
