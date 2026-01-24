//go:build acceptance

package acceptance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/integration/forms"
	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	"github.com/pomerium/pomerium/pkg/identity/pkce"
)

type pkceClaims struct {
	RawIDToken string
}

func (c *pkceClaims) SetRawIDToken(rawIDToken string) {
	c.RawIDToken = rawIDToken
}

func TestKeycloakPKCE(t *testing.T) {
	keycloakURL := getenvOrSkip(t, "KEYCLOAK_URL")
	realm := getenvOrDefault("KEYCLOAK_REALM", "pomerium")
	clientID := getenvOrSkip(t, "KEYCLOAK_CLIENT_ID")
	clientSecret := getenvOrSkip(t, "KEYCLOAK_CLIENT_SECRET")
	username := getenvOrSkip(t, "KEYCLOAK_USERNAME")
	password := getenvOrSkip(t, "KEYCLOAK_PASSWORD")
	redirectURI := getenvOrDefault("KEYCLOAK_REDIRECT_URI", "http://localhost:5555/callback")
	scopes := scopesFromEnvOrDefault("KEYCLOAK_SCOPES", []string{"openid", "profile", "email"})

	providerURL := strings.TrimSuffix(keycloakURL, "/") + "/realms/" + realm
	redirectURL, err := url.Parse(redirectURI)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	provider, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  providerURL,
		RedirectURL:  redirectURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
	})
	require.NoError(t, err)

	verifier := oauth2.GenerateVerifier()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(pkce.WithPKCE(req.Context(), pkce.Params{
		Verifier: verifier,
		Method:   "S256",
	}))
	rec := httptest.NewRecorder()
	require.NoError(t, provider.SignIn(rec, req, "STATE"))

	authURL := rec.Result().Header.Get("Location")
	require.NotEmpty(t, authURL)
	parsedAuthURL, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, "S256", parsedAuthURL.Query().Get("code_challenge_method"))
	require.True(t, oauth21.VerifyPKCES256(verifier, parsedAuthURL.Query().Get("code_challenge")))

	t.Logf("auth url: %s", authURL)
	code, state, err := loginAndGetCode(ctx, authURL, username, password)
	require.NoError(t, err)
	t.Logf("received code: %s state: %s", code, state)
	require.Equal(t, "STATE", state)

	capture := &tokenCapture{}
	authClient := &http.Client{
		Transport: captureRoundTripper{
			base:    http.DefaultTransport,
			capture: capture,
		},
	}
	pkceCtx := pkce.WithPKCE(ctx, pkce.Params{
		Verifier: verifier,
		Method:   "S256",
	})
	pkceCtx = context.WithValue(pkceCtx, oauth2.HTTPClient, authClient)
	var claims pkceClaims
	token, err := provider.Authenticate(pkceCtx, code, &claims)
	if err != nil {
		t.Logf("token request url: %s", capture.URL)
		t.Logf("token request body: %s", capture.Body)
	}
	require.NoError(t, err)
	require.NotEmpty(t, token.AccessToken)
	require.NotEmpty(t, claims.RawIDToken)
}

// TestKeycloakPKCEMultiTab verifies that two concurrent sign-in flows
// (simulating multiple browser tabs) each get independent PKCE verifiers
// and both complete successfully without interfering with each other.
func TestKeycloakPKCEMultiTab(t *testing.T) {
	keycloakURL := getenvOrSkip(t, "KEYCLOAK_URL")
	realm := getenvOrDefault("KEYCLOAK_REALM", "pomerium")
	clientID := getenvOrSkip(t, "KEYCLOAK_CLIENT_ID")
	clientSecret := getenvOrSkip(t, "KEYCLOAK_CLIENT_SECRET")
	username := getenvOrSkip(t, "KEYCLOAK_USERNAME")
	password := getenvOrSkip(t, "KEYCLOAK_PASSWORD")
	redirectURI := getenvOrDefault("KEYCLOAK_REDIRECT_URI", "http://localhost:5555/callback")
	scopes := scopesFromEnvOrDefault("KEYCLOAK_SCOPES", []string{"openid", "profile", "email"})

	providerURL := strings.TrimSuffix(keycloakURL, "/") + "/realms/" + realm
	redirectURL, err := url.Parse(redirectURI)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	provider, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  providerURL,
		RedirectURL:  redirectURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
	})
	require.NoError(t, err)

	// Simulate two tabs: generate two independent verifiers and sign-in URLs.
	type tabFlow struct {
		verifier string
		authURL  string
		state    string
	}
	tabs := make([]tabFlow, 2)
	for i := range tabs {
		tabs[i].verifier = oauth2.GenerateVerifier()
		tabs[i].state = fmt.Sprintf("STATE_TAB_%d", i)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(pkce.WithPKCE(req.Context(), pkce.Params{
			Verifier: tabs[i].verifier,
			Method:   "S256",
		}))
		rec := httptest.NewRecorder()
		require.NoError(t, provider.SignIn(rec, req, tabs[i].state))
		tabs[i].authURL = rec.Result().Header.Get("Location")
		require.NotEmpty(t, tabs[i].authURL)
	}

	// Complete the flows in reverse order (tab 1 first, then tab 0)
	// to prove ordering doesn't matter.
	for i := len(tabs) - 1; i >= 0; i-- {
		tab := tabs[i]
		t.Run(fmt.Sprintf("tab_%d", i), func(t *testing.T) {
			code, state, err := loginAndGetCode(ctx, tab.authURL, username, password)
			require.NoError(t, err)
			require.Equal(t, tab.state, state)

			pkceCtx := pkce.WithPKCE(ctx, pkce.Params{
				Verifier: tab.verifier,
				Method:   "S256",
			})
			var claims pkceClaims
			token, err := provider.Authenticate(pkceCtx, code, &claims)
			require.NoError(t, err, "tab %d should complete independently", i)
			require.NotEmpty(t, token.AccessToken)
			require.NotEmpty(t, claims.RawIDToken)
		})
	}
}

func loginAndGetCode(ctx context.Context, authURL, username, password string) (string, string, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return "", "", err
	}
	client := &http.Client{
		// Strip the Secure flag from response cookies so that Go's cookie jar
		// sends them back over plain HTTP. Keycloak 26+ sets Secure even in dev mode
		// (required by SameSite=None), but our tests use http://localhost.
		Transport: &stripSecureCookiesTransport{base: http.DefaultTransport},
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res, err := client.Get(authURL)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()

	if isRedirect(res.StatusCode) {
		return codeFromRedirect(res.Header.Get("Location"))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", "", err
	}
	formsParsed := forms.Parse(bytes.NewReader(body))
	if len(formsParsed) == 0 {
		return "", "", fmt.Errorf("no login form found")
	}

	form := formsParsed[0]
	form.Inputs["username"] = username
	form.Inputs["password"] = password

	req, err := form.NewRequestWithContext(ctx, res.Request.URL)
	if err != nil {
		return "", "", err
	}
	res2, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer res2.Body.Close()

	if !isRedirect(res2.StatusCode) {
		bodyBytes, _ := io.ReadAll(res2.Body)
		return "", "", fmt.Errorf("unexpected login response status %d: %s", res2.StatusCode, string(bodyBytes))
	}

	return codeFromRedirect(res2.Header.Get("Location"))
}

func codeFromRedirect(rawLocation string) (string, string, error) {
	location, err := url.Parse(rawLocation)
	if err != nil {
		return "", "", err
	}
	code := location.Query().Get("code")
	state := location.Query().Get("state")
	if code == "" {
		return "", "", fmt.Errorf("missing code in redirect")
	}
	return code, state, nil
}

func isRedirect(code int) bool {
	return code == http.StatusFound || code == http.StatusSeeOther || code == http.StatusTemporaryRedirect
}

type tokenCapture struct {
	URL  string
	Body string
}

type captureRoundTripper struct {
	base    http.RoundTripper
	capture *tokenCapture
}

func (c captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, "/token") && req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			c.capture.URL = req.URL.String()
			c.capture.Body = string(bodyBytes)
		}
	}
	return c.base.RoundTrip(req)
}

// stripSecureCookiesTransport removes the Secure flag from Set-Cookie headers
// so that Go's cookiejar sends them back over plain HTTP (test-only).
type stripSecureCookiesTransport struct {
	base http.RoundTripper
}

func (t *stripSecureCookiesTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	for i, c := range resp.Header.Values("Set-Cookie") {
		// Remove "; Secure" (case-insensitive) from cookie strings.
		cleaned := strings.Replace(c, ";Secure", "", 1)
		cleaned = strings.Replace(cleaned, "; Secure", "", 1)
		if i == 0 {
			resp.Header.Set("Set-Cookie", cleaned)
		} else {
			resp.Header.Add("Set-Cookie", cleaned)
		}
	}
	return resp, nil
}

func getenvOrSkip(t *testing.T, key string) string {
	t.Helper()
	if val := os.Getenv(key); val != "" {
		return val
	}
	t.Skipf("missing %s", key)
	return ""
}

func getenvOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func scopesFromEnvOrDefault(key string, fallback []string) []string {
	if val := os.Getenv(key); val != "" {
		fields := strings.Fields(val)
		if len(fields) > 0 {
			return fields
		}
	}
	return fallback
}
