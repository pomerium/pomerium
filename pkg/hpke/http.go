package hpke

import (
	"context"
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

// FetchPublicKey fetches the HPKE public key from the hpke-public-key endpoint.
func FetchPublicKey(ctx context.Context, client *http.Client, endpoint string) (*PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("hpke: error building hpke-public-key http request: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hpke: error requesting hpke-public-key endpoint: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("hpke: error requesting hpke-public-key endpoint, invalid status code: %d", res.StatusCode)
	}

	bs, err := io.ReadAll(io.LimitReader(res.Body, defaultMaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("hpke: error reading hpke-public-key endpoint: %w", err)
	}
	return PublicKeyFromBytes(bs)
}

// A KeyFetcher fetches public keys.
type KeyFetcher interface {
	FetchPublicKey(ctx context.Context) (*PublicKey, error)
}

type fetcher struct {
	client   *http.Client
	endpoint string
}

func (fetcher *fetcher) FetchPublicKey(ctx context.Context) (*PublicKey, error) {
	return FetchPublicKey(ctx, fetcher.client, fetcher.endpoint)
}

// NewKeyFetcher returns a new KeyFetcher which fetches keys using an in-memory HTTP cache.
func NewKeyFetcher(endpoint string, transport http.RoundTripper) KeyFetcher {
	return &fetcher{
		client: (&httpcache.Transport{
			Transport: transport,
			Cache:     httpcache.NewMemoryCache(),
		}).Client(),
		endpoint: endpoint,
	}
}
