package hpke

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gregjones/httpcache"
)

const (
	defaultMaxBodySize = 1024 * 1024 * 4

	jwkType  = "OKP"
	jwkID    = "pomerium/hpke"
	jwkCurve = "X25519"
)

// JWK is the JSON Web Key representation of an HPKE key.
// Defined in RFC8037.
type JWK struct {
	Type  string `json:"kty"`
	ID    string `json:"kid"`
	Curve string `json:"crv"`
	X     string `json:"x"`
	D     string `json:"d,omitempty"`
}

// FetchPublicKeyFromJWKS fetches the HPKE public key from the JWKS endpoint.
func FetchPublicKeyFromJWKS(ctx context.Context, client *http.Client, endpoint string) (PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return PublicKey{}, fmt.Errorf("hpke: error building jwks http request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return PublicKey{}, fmt.Errorf("hpke: error requesting jwks endpoint: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return PublicKey{}, fmt.Errorf("hpke: error requesting jwks endpoint, invalid status code: %d", res.StatusCode)
	}

	bs, err := io.ReadAll(io.LimitReader(res.Body, defaultMaxBodySize))
	if err != nil {
		return PublicKey{}, fmt.Errorf("hpke: error reading jwks endpoint: %d", res.StatusCode)
	}

	var jwks struct {
		Keys []JWK `json:"keys"`
	}
	err = json.Unmarshal(bs, &jwks)
	if err != nil {
		return PublicKey{}, fmt.Errorf("hpke: error unmarshaling jwks endpoint: %w", err)
	}

	for _, key := range jwks.Keys {
		if key.ID == jwkID && key.Type == jwkType && key.Curve == jwkCurve {
			return PublicKeyFromString(key.X)
		}
	}
	return PublicKey{}, fmt.Errorf("hpke key not found in JWKS endpoint")
}

// A KeyFetcher fetches public keys.
type KeyFetcher interface {
	FetchPublicKey(ctx context.Context) (PublicKey, error)
}

type jwksKeyFetcher struct {
	client   *http.Client
	endpoint string
}

func (fetcher *jwksKeyFetcher) FetchPublicKey(ctx context.Context) (PublicKey, error) {
	return FetchPublicKeyFromJWKS(ctx, fetcher.client, fetcher.endpoint)
}

// NewKeyFetcher returns a new KeyFetcher which fetches keys using an in-memory HTTP cache.
func NewKeyFetcher(endpoint string) KeyFetcher {
	return &jwksKeyFetcher{
		client:   httpcache.NewMemoryCacheTransport().Client(),
		endpoint: endpoint,
	}
}
