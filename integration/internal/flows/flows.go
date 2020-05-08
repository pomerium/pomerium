// Package flows has helper functions for working with pomerium end-user use-case flows.
package flows

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pomerium/pomerium/integration/internal/forms"
)

const (
	authenticateHostname = "authenticate.localhost.pomerium.io"
	openidHostname       = "openid.localhost.pomerium.io"
	pomeriumCallbackPath = "/.pomerium/callback/"
)

type authenticateConfig struct {
	email           string
	groups          []string
	tokenExpiration time.Duration
}

// An AuthenticateOption is an option for authentication.
type AuthenticateOption func(cfg *authenticateConfig)

func getAuthenticateConfig(options ...AuthenticateOption) *authenticateConfig {
	cfg := &authenticateConfig{
		tokenExpiration: time.Hour * 24,
	}
	for _, option := range options {
		option(cfg)
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

// Authenticate submits a request to a URL, expects a redirect to authenticate and then openid and logs in.
// Finally it expects to redirect back to the original page.
func Authenticate(ctx context.Context, client *http.Client, url *url.URL, options ...AuthenticateOption) (*http.Response, error) {
	cfg := getAuthenticateConfig(options...)
	originalHostname := url.Hostname()

	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
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
			return nil, fmt.Errorf("expected redirect to %s: %w", authenticateHostname, err)
		}
	}

	// (2) redirect to openid
	for req.URL.Hostname() == authenticateHostname {
		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		req, err = requestFromRedirectResponse(ctx, res, req)
		if err != nil {
			return nil, fmt.Errorf("expected redirect to %s: %w", openidHostname, err)
		}
	}

	// (3) submit the form
	for req.URL.Hostname() == openidHostname {
		res, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		forms := forms.Parse(res.Body)
		if len(forms) > 0 {
			f := forms[0]
			f.Inputs["email"] = cfg.email
			if len(cfg.groups) > 0 {
				f.Inputs["groups"] = strings.Join(cfg.groups, ",")
			}
			f.Inputs["token_expiration"] = strconv.Itoa(int(cfg.tokenExpiration.Seconds()))
			req, err = f.NewRequestWithContext(ctx, req.URL)
			if err != nil {
				return nil, err
			}
		} else {
			req, err = requestFromRedirectResponse(ctx, res, req)
			if err != nil {
				return nil, fmt.Errorf("expected redirect to %s: %w", openidHostname, err)
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
			return nil, fmt.Errorf("expected redirect to %s: %w", originalHostname, err)
		}
	}

	// (5) finally to callback
	if req.URL.Path != pomeriumCallbackPath {
		return nil, fmt.Errorf("expected to redirect back to %s, but got %s", pomeriumCallbackPath, req.URL.String())
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

	return client.Do(req)
}

func requestFromRedirectResponse(ctx context.Context, res *http.Response, req *http.Request) (*http.Request, error) {
	if res.Header.Get("Location") == "" {
		return nil, fmt.Errorf("no location header found in response headers")
	}
	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	location = req.URL.ResolveReference(location)
	newreq, err := http.NewRequestWithContext(ctx, "GET", location.String(), nil)
	if err != nil {
		return nil, err
	}
	return newreq, nil
}
