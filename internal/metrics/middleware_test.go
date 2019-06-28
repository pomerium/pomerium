package metrics // import "github.com/pomerium/pomerium/internal/metrics"

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/tripper"
	"go.opencensus.io/stats/view"
)

type measure struct {
	Name    string
	Tags    map[string]string
	Measure int
}

func newTestMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/good", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	})

	return mux
}

func Test_HTTPMetricsHandler(t *testing.T) {

	chain := middleware.NewChain()
	chain = chain.Append(HTTPMetricsHandler("test_service"))
	chainHandler := chain.Then(newTestMux())

	tests := []struct {
		name                          string
		url                           string
		verb                          string
		wanthttpServerResponseSize    string
		wanthttpServerRequestDuration string
		wanthttpServerRequestCount    string
	}{
		{
			name:                          "good get",
			url:                           "http://test.local/good",
			verb:                          "GET",
			wanthttpServerResponseSize:    "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerRequestDuration: "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1",
			wanthttpServerRequestCount:    "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1",
		},
		{
			name:                          "good post",
			url:                           "http://test.local/good",
			verb:                          "POST",
			wanthttpServerResponseSize:    "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerRequestDuration: "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1",
			wanthttpServerRequestCount:    "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1",
		},
		{
			name:                          "bad post",
			url:                           "http://test.local/bad",
			verb:                          "POST",
			wanthttpServerResponseSize:    "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1 19 19 19 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerRequestDuration: "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1",
			wanthttpServerRequestCount:    "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view.Unregister(HTTPServerRequestCountView, HTTPServerRequestDurationView, HTTPServerRequestSizeView)
			view.Register(HTTPServerRequestCountView, HTTPServerRequestDurationView, HTTPServerRequestSizeView)

			req := httptest.NewRequest(tt.verb, tt.url, new(bytes.Buffer))
			rec := httptest.NewRecorder()
			chainHandler.ServeHTTP(rec, req)

			testDataRetrieval(httpServerResponseSize, t, tt.wanthttpServerResponseSize)
			testDataRetrieval(httpServerRequestDuration, t, tt.wanthttpServerRequestDuration)
			testDataRetrieval(httpServerRequestCount, t, tt.wanthttpServerRequestCount)
		})
	}
}

func newTestTransport() http.RoundTripper {
	return tripper.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		resp := httptest.NewRecorder()
		newTestMux().ServeHTTP(resp, r)
		resp.Flush()
		result := resp.Result()

		// This really looks like a regression / bug?
		// https://github.com/golang/go/issues/16952
		result.ContentLength = int64(len(resp.Body.Bytes()))
		return result, nil
	})
}

func newFailingTestTransport() http.RoundTripper {
	return tripper.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("failure")
	})
}

func Test_HTTPMetricsRoundTripper(t *testing.T) {
	chain := tripper.NewChain(HTTPMetricsRoundTripper("test_service"))
	rt := chain.Then(newTestTransport())
	client := http.Client{Transport: rt}

	tests := []struct {
		name                          string
		url                           string
		verb                          string
		wanthttpClientResponseSize    string
		wanthttpClientRequestDuration string
		wanthttpClientRequestCount    string
	}{
		{
			name:                          "good get",
			url:                           "http://test.local/good",
			verb:                          "GET",
			wanthttpClientResponseSize:    "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientRequestDuration: "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1",
			wanthttpClientRequestCount:    "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1",
		},
		{
			name:                          "good post",
			url:                           "http://test.local/good",
			verb:                          "POST",
			wanthttpClientResponseSize:    "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientRequestDuration: "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1",
			wanthttpClientRequestCount:    "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1",
		},
		{
			name:                          "bad post",
			url:                           "http://test.local/bad",
			verb:                          "POST",
			wanthttpClientResponseSize:    "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1 19 19 19 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientRequestDuration: "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1",
			wanthttpClientRequestCount:    "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view.Unregister(HTTPClientRequestCountView, HTTPClientRequestDurationView, HTTPClientResponseSizeView)
			view.Register(HTTPClientRequestCountView, HTTPClientRequestDurationView, HTTPClientResponseSizeView)

			req, _ := http.NewRequest(tt.verb, tt.url, new(bytes.Buffer))
			resp, err := client.Do(req)

			t.Logf("response: %#v, %#v", resp, err)
			testDataRetrieval(httpClientResponseSize, t, tt.wanthttpClientResponseSize)
			testDataRetrieval(httpClientRequestDuration, t, tt.wanthttpClientRequestDuration)
			testDataRetrieval(httpClientRequestCount, t, tt.wanthttpClientRequestCount)
		})
	}

	// Check for transport Errors
	client = http.Client{Transport: chain.Then(newFailingTestTransport())}
	req, _ := http.NewRequest("GET", "http://test.local", new(bytes.Buffer))
	resp, err := client.Do(req)
	if err == nil || resp != nil {
		t.Error("Transport error not surfaced properly")
	}
}
