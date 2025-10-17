package urlutil

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/hpke"
)

// DefaultDeviceType is the default device type when none is specified.
const DefaultDeviceType = "any"

const signInExpiry = time.Minute * 5

var (
	pomeriumRuntime = os.Getenv("POMERIUM_RUNTIME")
	pomeriumArch    = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
)

func versionStr() string {
	return strings.Join([]string{version.FullVersion(), pomeriumArch, pomeriumRuntime}, " ")
}

// CallbackURL builds the callback URL using an HPKE encrypted query string.
func CallbackURL(
	authenticatePrivateKey *hpke.PrivateKey,
	proxyPublicKey *hpke.PublicKey,
	requestParams url.Values,
	profile *identity.Profile,
	encryptURLValues hpke.EncryptURLValuesFunc,
) (string, error) {
	redirectURL, err := ParseAndValidateURL(requestParams.Get(QueryRedirectURI))
	if err != nil {
		return "", fmt.Errorf("invalid %s: %w", QueryRedirectURI, err)
	}

	var callbackURL *url.URL
	if requestParams.Has(QueryCallbackURI) {
		callbackURL, err = ParseAndValidateURL(requestParams.Get(QueryCallbackURI))
		if err != nil {
			return "", fmt.Errorf("invalid %s: %w", QueryCallbackURI, err)
		}
	} else {
		callbackURL, err = DeepCopy(redirectURL)
		if err != nil {
			return "", fmt.Errorf("error copying %s: %w", QueryRedirectURI, err)
		}
		callbackURL.Path = "/.pomerium/callback/"
		callbackURL.RawQuery = ""
	}

	callbackParams := callbackURL.Query()
	if requestParams.Has(QueryIsProgrammatic) {
		callbackParams.Set(QueryIsProgrammatic, "true")
	}
	callbackParams.Set(QueryRedirectURI, redirectURL.String())

	rawProfile, err := protojson.Marshal(profile)
	if err != nil {
		return "", fmt.Errorf("error marshaling identity profile: %w", err)
	}
	callbackParams.Set(QueryIdentityProfile, string(rawProfile))
	callbackParams.Set(QueryVersion, versionStr())

	BuildTimeParameters(callbackParams, signInExpiry)

	callbackParams, err = encryptURLValues(authenticatePrivateKey, proxyPublicKey, callbackParams)
	if err != nil {
		return "", fmt.Errorf("error encrypting callback params: %w", err)
	}
	callbackURL.RawQuery = callbackParams.Encode()

	return callbackURL.String(), nil
}

// RedirectURL returns the redirect URL from the query string or a cookie.
func RedirectURL(r *http.Request) (string, bool) {
	if v := r.FormValue(QueryRedirectURI); v != "" {
		return v, true
	}

	if c, err := r.Cookie(QueryRedirectURI); err == nil {
		return c.Value, true
	}

	return "", false
}

// SignInURL builds the sign in URL using an HPKE encrypted query string.
func SignInURL(
	senderPrivateKey *hpke.PrivateKey,
	authenticatePublicKey *hpke.PublicKey,
	authenticateURL *url.URL,
	redirectURL *url.URL,
	idpID string,
) (string, error) {
	signInURL := *authenticateURL
	signInURL.Path = endpoints.PathPomeriumSignIn

	q := signInURL.Query()
	q.Set(QueryRedirectURI, redirectURL.String())
	q.Set(QueryIdentityProviderID, idpID)
	q.Set(QueryVersion, versionStr())
	q.Set(QueryRequestUUID, uuid.NewString())
	BuildTimeParameters(q, signInExpiry)
	q, err := hpke.EncryptURLValuesV2(senderPrivateKey, authenticatePublicKey, q)
	if err != nil {
		return "", err
	}
	signInURL.RawQuery = q.Encode()

	return signInURL.String(), nil
}

// SignOutURL returns the /.pomerium/sign_out URL.
func SignOutURL(r *http.Request, authenticateURL *url.URL, key []byte) string {
	u := authenticateURL.ResolveReference(&url.URL{
		Path: endpoints.PathPomeriumSignOut,
	})
	q := u.Query()
	if redirectURI, ok := RedirectURL(r); ok {
		q.Set(QueryRedirectURI, redirectURI)
	}
	q.Set(QueryVersion, versionStr())
	u.RawQuery = q.Encode()
	return NewSignedURL(key, u).Sign().String()
}

// WebAuthnURL returns the /.pomerium/webauthn URL.
func WebAuthnURL(_ *http.Request, authenticateURL *url.URL, key []byte, values url.Values) string {
	u := authenticateURL.ResolveReference(&url.URL{
		Path: endpoints.PathPomeriumWebAuthn,
		RawQuery: buildURLValues(values, url.Values{
			QueryDeviceType:      {DefaultDeviceType},
			QueryEnrollmentToken: nil,
			QueryRedirectURI: {authenticateURL.ResolveReference(&url.URL{
				Path: endpoints.PathPomeriumDeviceEnrolled,
			}).String()},
		}).Encode(),
	})
	return NewSignedURL(key, u).Sign().String()
}

func buildURLValues(values, defaults url.Values) url.Values {
	result := make(url.Values)
	for k, vs := range defaults {
		if values.Has(k) {
			result[k] = values[k]
		} else if vs != nil {
			result[k] = vs
		}
	}
	return result
}
