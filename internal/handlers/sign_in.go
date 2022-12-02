package handlers

import (
	"fmt"
	"net/url"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/hpke"
)

const signInExpiry = time.Minute * 5

// BuildCallbackURL builds the callback URL using an HPKE encrypted query string.
func BuildCallbackURL(
	authenticatePrivateKey *hpke.PrivateKey,
	proxyPublicKey *hpke.PublicKey,
	requestParams url.Values,
	profile *identity.Profile,
) (string, error) {
	redirectURL, err := urlutil.ParseAndValidateURL(requestParams.Get(urlutil.QueryRedirectURI))
	if err != nil {
		return "", fmt.Errorf("invalid %s: %w", urlutil.QueryRedirectURI, err)
	}

	var callbackURL *url.URL
	if requestParams.Has(urlutil.QueryCallbackURI) {
		callbackURL, err = urlutil.ParseAndValidateURL(requestParams.Get(urlutil.QueryCallbackURI))
		if err != nil {
			return "", fmt.Errorf("invalid %s: %w", urlutil.QueryCallbackURI, err)
		}
	} else {
		callbackURL, err = urlutil.DeepCopy(redirectURL)
		if err != nil {
			return "", fmt.Errorf("error copying %s: %w", urlutil.QueryRedirectURI, err)
		}
		callbackURL.Path = "/.pomerium/callback"
		callbackURL.RawQuery = ""
	}

	callbackParams := callbackURL.Query()
	if requestParams.Has(urlutil.QueryIsProgrammatic) {
		callbackParams.Set(urlutil.QueryIsProgrammatic, "true")
	}
	callbackParams.Set(urlutil.QueryRedirectURI, redirectURL.String())

	rawProfile, err := protojson.Marshal(profile)
	if err != nil {
		return "", fmt.Errorf("error marshaling identity profile: %w", err)
	}
	callbackParams.Set(urlutil.QueryIdentityProfile, string(rawProfile))

	urlutil.BuildTimeParameters(callbackParams, signInExpiry)

	callbackParams, err = hpke.EncryptURLValues(authenticatePrivateKey, proxyPublicKey, callbackParams)
	if err != nil {
		return "", fmt.Errorf("error encrypting callback params: %w", err)
	}
	callbackURL.RawQuery = callbackParams.Encode()

	return callbackURL.String(), nil
}

// BuildSignInURL buidls the sign in URL using an HPKE encrypted query string.
func BuildSignInURL(
	senderPrivateKey *hpke.PrivateKey,
	authenticatePublicKey *hpke.PublicKey,
	authenticateURL *url.URL,
	redirectURL *url.URL,
	idpID string,
) (string, error) {
	signInURL := authenticateURL.ResolveReference(&url.URL{
		Path: "/.pomerium/sign_in",
	})

	q := signInURL.Query()
	q.Set(urlutil.QueryRedirectURI, redirectURL.String())
	q.Set(urlutil.QueryIdentityProviderID, idpID)
	urlutil.BuildTimeParameters(q, signInExpiry)
	q, err := hpke.EncryptURLValues(senderPrivateKey, authenticatePublicKey, q)
	if err != nil {
		return "", err
	}
	signInURL.RawQuery = q.Encode()

	return signInURL.String(), nil
}
