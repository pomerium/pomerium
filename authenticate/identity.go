package authenticate

import (
	"context"

	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/identity"
)

func defaultGetIdentityProvider(ctx context.Context, tracerProvider oteltrace.TracerProvider, options *config.Options, idpID string) (identity.Authenticator, error) {
	redirectURL, err := options.GetAuthenticateRedirectURL()
	if err != nil {
		return nil, err
	}

	idp, err := options.GetIdentityProviderForID(idpID)
	if err != nil {
		return nil, err
	}

	return identity.GetIdentityProvider(ctx, tracerProvider, idp, redirectURL,
		options.RuntimeFlags[config.RuntimeFlagRefreshSessionAtIDTokenExpiration])
}
