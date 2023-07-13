package hpke

import (
	"context"
)

type stubFetcher struct {
	key *PublicKey
}

func (f stubFetcher) FetchPublicKey(_ context.Context) (*PublicKey, error) {
	return f.key, nil
}

// NewStubKeyFetcher returns a new KeyFetcher which returns a fixed key.
func NewStubKeyFetcher(key *PublicKey) KeyFetcher {
	return stubFetcher{key}
}
