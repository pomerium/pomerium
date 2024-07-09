package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/urlutil"
)

type RouteMatcher interface {
	GetIdentityProviderForRequest(r *http.Request) (string, error)
}

type RouteMatcherFunc func(r *http.Request) (string, error)

func (f RouteMatcherFunc) GetIdentityProviderForRequest(r *http.Request) (string, error) {
	return f(r)
}

func newCheckRouteAPIMatcher(state *atomicutil.Value[*proxyState]) RouteMatcher {
	return &checkRouteAPIMatcher{state: state}
}

type checkRouteAPIMatcher struct {
	state *atomicutil.Value[*proxyState]
}

func (l *checkRouteAPIMatcher) GetIdentityProviderForRequest(r *http.Request) (string, error) {
	requestURL := urlutil.NewSignedURL(
		l.state.Load().cookieSecret,
		urlutil.GetAbsoluteURL(r).ResolveReference(&url.URL{
			Path: r.FormValue(urlutil.QueryRequestPath),
		}),
	)

	ctx, ca := context.WithTimeout(r.Context(), 10*time.Second)
	defer ca()
	req, _ := http.NewRequestWithContext(ctx, r.Method, requestURL.String(), nil)
	req.Header.Set("X-Pomerium-Check-Route", "1")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.Status, errors.New(resp.Status)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		return "", fmt.Errorf("unexpected Content-Type %q returned from route check", resp.Header.Get("Content-Type"))
	}
	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	type checkRouteResponse struct {
		RouteID string `json:"route_id"`
	}
	var cr checkRouteResponse
	if err := json.Unmarshal(jsonData, &cr); err != nil {
		return "", err
	}
	return cr.RouteID, nil
}
