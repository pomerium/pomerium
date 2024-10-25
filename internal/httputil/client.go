package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/tripper"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

// ErrTokenRevoked signifies a token revocation or expiration error
var ErrTokenRevoked = errors.New("token expired or revoked")

type loggingRoundTripper struct {
	base      http.RoundTripper
	customize []func(event *zerolog.Event) *zerolog.Event
}

func (l loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	res, err := l.base.RoundTrip(req)
	statusCode := http.StatusInternalServerError
	if res != nil {
		statusCode = res.StatusCode
	}
	evt := log.Ctx(req.Context()).Debug().
		Str("method", req.Method).
		Str("authority", req.URL.Host).
		Str("path", req.URL.Path).
		Dur("duration", time.Since(start)).
		Int("response-code", statusCode)
	for _, f := range l.customize {
		f(evt)
	}
	evt.Msg("outbound http-request")
	return res, err
}

// NewLoggingRoundTripper creates a http.RoundTripper that will log requests.
func NewLoggingRoundTripper(base http.RoundTripper, customize ...func(event *zerolog.Event) *zerolog.Event) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return loggingRoundTripper{base: base, customize: customize}
}

// NewLoggingClient creates a new http.Client that will log requests.
func NewLoggingClient(base *http.Client, name string, customize ...func(event *zerolog.Event) *zerolog.Event) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	newClient := new(http.Client)
	*newClient = *base
	newClient.Transport = tripper.NewChain(metrics.HTTPMetricsRoundTripper(func() string {
		return ""
	}, name)).Then(NewLoggingRoundTripper(newClient.Transport, customize...))

	return newClient
}

type httpClient struct {
	*http.Client
	requestIDTripper http.RoundTripper
}

func (c *httpClient) Do(req *http.Request) (*http.Response, error) {
	tripperChain := tripper.NewChain(metrics.HTTPMetricsRoundTripper(func() string {
		return ""
	}, "idp_http_client"))
	c.Client.Transport = tripperChain.Then(c.requestIDTripper)
	return c.Client.Do(req)
}

// getDefaultClient returns an HTTP client that avoids leaks by setting an upper limit for timeouts.
func getDefaultClient() *httpClient {
	return &httpClient{
		&http.Client{Timeout: 1 * time.Minute},
		requestid.NewRoundTripper(http.DefaultTransport),
	}
}

// Do provides a simple helper interface to make HTTP requests
func Do(ctx context.Context, method, endpoint, userAgent string, headers map[string]string, params url.Values, response any) error {
	var body io.Reader
	switch method {
	case http.MethodPost:
		body = bytes.NewBufferString(params.Encode())
	case http.MethodGet:
		// error checking skipped because we are just parsing in
		// order to make a copy of an existing URL
		if params != nil {
			u, _ := url.Parse(endpoint)
			u.RawQuery = params.Encode()
			endpoint = u.String()
		}
	default:
		return errors.New(http.StatusText(http.StatusBadRequest))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := getDefaultClient().Do(req)
	if err != nil {
		return err
	}

	var respBody []byte
	respBody, err = io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusBadRequest:
			var response struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			e := json.Unmarshal(respBody, &response)
			if e == nil && response.ErrorDescription == "Token expired or revoked" {
				return ErrTokenRevoked
			}
			return errors.New(http.StatusText(http.StatusBadRequest))
		default:
			return errors.New(http.StatusText(resp.StatusCode))
		}
	}
	if response != nil {
		err := json.Unmarshal(respBody, &response)
		if err != nil {
			return err
		}
	}
	return nil
}
