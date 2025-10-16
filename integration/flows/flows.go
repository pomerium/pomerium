// Package flows has helper functions for working with pomerium end-user use-case flows.
package flows

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pomerium/pomerium/integration/forms"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

const (
	authenticateHostname = "authenticate.localhost.pomerium.io"
	idpHostname          = "mock-idp.localhost.pomerium.io"
	pomeriumCallbackPath = "/.pomerium/callback/"
)

type authenticateConfig struct {
	email           string
	groups          []string
	tokenExpiration time.Duration
	apiPath         string
	requestHeaders  http.Header
}

// An AuthenticateOption is an option for authentication.
type AuthenticateOption func(cfg *authenticateConfig)

func getAuthenticateConfig(options ...AuthenticateOption) *authenticateConfig {
	cfg := &authenticateConfig{
		tokenExpiration: time.Hour * 24,
		requestHeaders:  http.Header{},
	}
	for _, option := range options {
		if option != nil {
			option(cfg)
		}
	}
	return cfg
}

// WithEmail sets the email to use.
func WithEmail(email string) AuthenticateOption {
	return func(cfg *authenticateConfig) {
		cfg.email = email
	}
}

// WithGroups sets the groups to use.
func WithGroups(groups ...string) AuthenticateOption {
	return func(cfg *authenticateConfig) {
		cfg.groups = groups
	}
}

// WithTokenExpiration sets the token expiration.
func WithTokenExpiration(tokenExpiration time.Duration) AuthenticateOption {
	return func(cfg *authenticateConfig) {
		cfg.tokenExpiration = tokenExpiration
	}
}

// WithAPI tells authentication to use API authentication flow.
func WithAPI() AuthenticateOption {
	return func(cfg *authenticateConfig) {
		cfg.apiPath = endpoints.PathPomeriumAPILogin
	}
}

func WithRequestHeader(name, value string) AuthenticateOption {
	return func(cfg *authenticateConfig) {
		cfg.requestHeaders.Set(name, value)
	}
}

// Authenticate submits a request to a URL, expects a redirect to authenticate and then openid and logs in.
// Finally it expects to redirect back to the original page.
func Authenticate(ctx context.Context, client *http.Client, url *url.URL, options ...AuthenticateOption) (*http.Response, error) {
	cfg := getAuthenticateConfig(options...)
	originalHostname := url.Hostname()
	var err error

	// Serve a local callback for programmatic redirect flow
	srv := httptest.NewUnstartedServer(http.RedirectHandler(url.String(), http.StatusFound))
	defer srv.Close()

	if cfg.apiPath != "" {
		srv.Start()
		apiLogin := url
		q := apiLogin.Query()
		q.Set(urlutil.QueryRedirectURI, srv.URL)
		apiLogin.RawQuery = q.Encode()

		apiLogin.Path = cfg.apiPath
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiLogin.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("via-api: invalid request: %w", err)
		}
		req.Header.Set("Accept", "application/json")

		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("via-api: error making request: %w", err)
		}
		defer res.Body.Close()
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("via-api: error reading response body: %w", err)
		}
		url, err = url.Parse(string(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("via-api: error parsing response body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}

	var res *http.Response

	// (1) redirect to authenticate
	for req.URL.Hostname() == originalHostname {
		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		req, err = requestFromRedirectResponse(ctx, res, req)
		if err != nil {
			return nil, fmt.Errorf("expected redirect 1 to %s: %w", authenticateHostname, err)
		}
	}

	// (2) redirect to idp
	for req.URL.Hostname() == authenticateHostname {
		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		req, err = requestFromRedirectResponse(ctx, res, req)
		if err != nil {
			return nil, fmt.Errorf("expected redirect 2 to %s: %w", idpHostname, err)
		}
	}

	// (3) submit the form
	for req.URL.Hostname() == idpHostname {
		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		fs := forms.Parse(res.Body)
		if len(fs) > 0 {
			f := fs[0]
			f.Inputs["email"] = cfg.email
			if len(cfg.groups) > 0 {
				f.Inputs["groups"] = strings.Join(cfg.groups, ",")
			}
			f.Inputs["token_expiration"] = strconv.Itoa(int(cfg.tokenExpiration.Seconds()))
			req, err = f.NewRequestWithContext(ctx, req.URL)
			if err != nil {
				return nil, err
			}
			addRequestHeaders(req, cfg.requestHeaders)
		} else {
			req, err = requestFromRedirectResponse(ctx, res, req)
			if err != nil {
				return nil, fmt.Errorf("expected redirect 3 to %s: %w", idpHostname, err)
			}
		}
	}

	// (4) back to authenticate
	for req.URL.Hostname() == authenticateHostname {
		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		req, err = requestFromRedirectResponse(ctx, res, req)
		if err != nil {
			return nil, fmt.Errorf("expected redirect 4 to %s: %w", originalHostname, err)
		}
	}

	// (5) finally to callback
	if req.URL.Path != pomeriumCallbackPath {
		return nil, fmt.Errorf("expected to redirect 5 back to %s, but got %s", pomeriumCallbackPath, req.URL.String())
	}

	res, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	req, err = requestFromRedirectResponse(ctx, res, req)
	if err != nil {
		return nil, fmt.Errorf("expected redirect to %s: %w", originalHostname, err)
	}

	// Programmatic flow: Follow redirect from local callback
	if cfg.apiPath != "" {
		req, err = requestFromRedirectResponse(ctx, res, req)
		if err != nil {
			return nil, fmt.Errorf("expected redirect to %s: %w", srv.URL, err)
		}
		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		req, err = requestFromRedirectResponse(ctx, res, req)
		if err != nil {
			return nil, fmt.Errorf("expected redirect to %s: %w", originalHostname, err)
		}
	}

	return client.Do(req)
}

func requestFromRedirectResponse(ctx context.Context, res *http.Response, req *http.Request) (*http.Request, error) {
	if res.Header.Get("Location") == "" {
		return nil, fmt.Errorf("no location header found in response headers")
	}
	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		return nil, fmt.Errorf("error parsing location: %w", err)
	}
	location = req.URL.ResolveReference(location)
	newreq, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return nil, err
	}
	addRequestHeaders(newreq, req.Header)
	return newreq, nil
}

func addRequestHeaders(req *http.Request, headers http.Header) {
	for h := range headers {
		req.Header[h] = headers[h]
	}
}
