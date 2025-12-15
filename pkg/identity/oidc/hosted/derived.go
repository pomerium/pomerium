package hosted

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/url"

	"golang.org/x/crypto/hkdf"

	"github.com/pomerium/pomerium/pkg/grpc/identity"
)

// Options contains just the methods of config.Options needed for the derived
// provider info (to avoid an import cycle).
type Options interface {
	GetAuthenticateURL() (*url.URL, error)
	GetSharedKey() ([]byte, error)
}

// DeriveProviderInfo populates some of the Provider details for use with the
// Hosted Authenticate OIDC flow. The client ID and secret are populated from
// the authenticate service URL and the shared secret. The provider URL is set
// to the default Hosted Authenticate URL if empty.
func DeriveProviderInfo(idp *identity.Provider, o Options) error {
	authenticateURL, err := o.GetAuthenticateURL()
	if err != nil {
		return err
	}
	secret, err := o.GetSharedKey()
	if err != nil {
		return err
	}
	r := hkdf.New(sha256.New, secret, nil, []byte("hosted-authenticate-derived-jwk"))
	_, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return err
	}
	idp.ClientId = authenticateURL.String()
	idp.ClientSecret = base64.RawStdEncoding.EncodeToString(priv)

	if idp.Url == "" {
		idp.Url = DefaultProviderURL
	}
	return nil
}
