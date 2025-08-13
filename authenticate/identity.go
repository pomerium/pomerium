package authenticate

import (
	"cmp"
	"context"
	"net/url"
	"sync"

	"github.com/google/btree"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/identity"
)

type cachedAuthenticator struct {
	redirectURL               *url.URL
	idp                       *identitypb.Provider
	overwriteIDTokenOnRefresh bool
	authenticator             identity.Authenticator
}

var cachedAuthenticators = struct {
	sync.RWMutex
	*btree.BTreeG[cachedAuthenticator]
}{
	BTreeG: btree.NewG(2, func(a, b cachedAuthenticator) bool {
		return cmp.Or(
			compareURLs(a.redirectURL, b.redirectURL),
			cmp.Compare(a.idp.Hash(), b.idp.Hash()),
			compareBools(a.overwriteIDTokenOnRefresh, b.overwriteIDTokenOnRefresh),
		) < 0
	}),
}

func defaultGetIdentityProvider(ctx context.Context, tracerProvider oteltrace.TracerProvider, options *config.Options, idpID string) (identity.Authenticator, error) {
	var err error
	key := cachedAuthenticator{}

	key.redirectURL, err = options.GetAuthenticateRedirectURL()
	if err != nil {
		return nil, err
	}

	key.idp, err = options.GetIdentityProviderForID(idpID)
	if err != nil {
		return nil, err
	}

	key.overwriteIDTokenOnRefresh = options.RuntimeFlags[config.RuntimeFlagRefreshSessionAtIDTokenExpiration]

	cachedAuthenticators.RLock()
	value, ok := cachedAuthenticators.Get(key)
	cachedAuthenticators.RUnlock()
	if ok {
		return value.authenticator, nil
	}

	cachedAuthenticators.Lock()
	defer cachedAuthenticators.Unlock()

	value, ok = cachedAuthenticators.Get(key)
	if ok {
		return value.authenticator, nil
	}

	key.authenticator, err = identity.GetIdentityProvider(ctx, tracerProvider, key.idp, key.redirectURL, key.overwriteIDTokenOnRefresh)
	if err != nil {
		return nil, err
	}

	cachedAuthenticators.ReplaceOrInsert(key)

	return key.authenticator, nil
}

func compareBools(a, b bool) int {
	switch {
	case a && !b:
		return -1
	case b && !a:
		return 1
	default:
		return 0
	}
}

func compareURLs(a, b *url.URL) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}

	return cmp.Compare(a.String(), b.String())
}
