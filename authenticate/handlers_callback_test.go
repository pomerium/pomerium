package authenticate_test

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestCallback(t *testing.T) {
	t.Setenv("DEBUG_FORCE_AUTHENTICATE_FLOW", "stateless")

	idp := mockidp.New(mockidp.Config{})
	idpURL := idp.Start(t)

	options := config.NewDefaultOptions()
	options.CookieSecret = cryptutil.NewBase64Key()
	options.SharedKey = cryptutil.NewBase64Key()
	options.Provider = "oidc"
	options.ProviderURL = idpURL
	options.ClientID = "CLIENT_ID"
	options.ClientSecret = "CLIENT_SECRET"
	a, err := authenticate.New(t.Context(), &config.Config{Options: options})
	require.NoError(t, err)

	srv := httptest.NewTLSServer(a)
	t.Cleanup(srv.Close)
	options.AuthenticateURLString = srv.URL
	options.AuthenticateCallbackPath = "/test/callback"
	a.OnConfigChange(t.Context(), &config.Config{Options: options})

	cj, err := cookiejar.New(nil)
	require.NoError(t, err)
	c := &http.Client{
		Transport: httputil.GetInsecureTransport(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: cj,
	}

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/.pomerium/sign_in", nil)
	require.NoError(t, err)
	res, err := c.Do(r)
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, res.StatusCode)
	_ = res.Body.Close()

	u, err := url.Parse(res.Header.Get("Location"))
	require.NoError(t, err)
	q := u.Query()
	q.Add("email", "u1@example.com")
	u.RawQuery = q.Encode()

	r, err = http.NewRequestWithContext(t.Context(), http.MethodGet, u.String(), nil)
	require.NoError(t, err)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err = c.Do(r)
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, res.StatusCode)
	_ = res.Body.Close()

	r, err = http.NewRequestWithContext(t.Context(), http.MethodGet, res.Header.Get("Location"), nil)
	require.NoError(t, err)
	res, err = c.Do(r)
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, res.StatusCode)
	_ = res.Body.Close()
}
