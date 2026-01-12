package internal

import (
	"context"
	"errors"
	"fmt"

	go_oidc "github.com/coreos/go-oidc/v3/oidc"
)

var ErrMissingIDToken = errors.New("identity/oidc: missing id_token")

type Provider interface {
	GetVerifier() (*go_oidc.IDTokenVerifier, error)
}

func VerifyIDToken(ctx context.Context, provider Provider, rawIDToken string) (*go_oidc.IDToken, error) {
	if rawIDToken == "" {
		return nil, ErrMissingIDToken
	}

	v, err := provider.GetVerifier()
	if err != nil {
		return nil, fmt.Errorf("error getting verifier: %w", err)
	}

	token, err := v.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("error verifying token: %w", err)
	}
	return token, nil
}
