// Package flows has helper functions for working with pomerium end-user use-case flows.
package flows

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/integration/internal/forms"
)

const (
	authenticateHostname = "authenticate.localhost.pomerium.io"
	openidHostname       = "openid.localhost.pomerium.io"
	pomeriumCallbackPath = "/.pomerium/callback/"
)

// Authenticate submits a request to a URL, expects a redirect to authenticate and then openid and logs in.
// Finally it expects to redirect back to the original page.
func Authenticate(ctx context.Context, client *http.Client, url *url.URL, email string, groups []string) (*http.Response, error) {
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
			f.Inputs["email"] = email
			f.Inputs["groups"] = strings.Join(groups, ",")
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
