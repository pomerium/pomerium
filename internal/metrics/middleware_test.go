package metrics // import "github.com/pomerium/pomerium/internal/metrics"

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
			view.Unregister(views...)
			view.Register(views...)

			req := httptest.NewRequest(tt.verb, tt.url, new(bytes.Buffer))
			rec := httptest.NewRecorder()
			chainHandler.ServeHTTP(rec, req)

			// httpResponseSize
			data, _ := view.RetrieveData(httpServerResponseSize.Name())
			if len(data) != 1 {
				t.Errorf("httpServerResponseSize: received wrong number of data rows: %d", len(data))
				return
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpServerResponseSize) {
				t.Errorf("httpServerResponseSize: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpServerResponseSize, data[0].String())
			}

			// httpRequestDuration
			data, _ = view.RetrieveData(httpServerRequestDuration.Name())
			if len(data) != 1 {
				t.Errorf("httpServerRequestDuration: received too many data rows: %d", len(data))
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpServerRequestDuration) {
				t.Errorf("httpServerRequestDuration: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpServerRequestDuration, data[0].String())
			}

			// httpRequestCount
			data, _ = view.RetrieveData(httpServerRequestCount.Name())
			if len(data) != 1 {
				t.Errorf("httpServerRequestCount: received too many data rows: %d", len(data))
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpServerRequestCount) {
				t.Errorf("httpServerRequestCount: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpServerRequestCount, data[0].String())
			}
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
			view.Unregister(views...)
			view.Register(views...)

			req, _ := http.NewRequest(tt.verb, tt.url, new(bytes.Buffer))
			resp, err := client.Do(req)

			t.Logf("response: %#v, %#v", resp, err)

			// httpClientResponseSize
			data, _ := view.RetrieveData(httpClientResponseSize.Name())
			if len(data) != 1 {
				t.Errorf("httpClientResponseSize: received wrong number of data rows: %d", len(data))
				return
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpClientResponseSize) {
				t.Errorf("httpResponseSize: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpClientResponseSize, data[0].String())
			}

			// httpClientRequestDuration
			data, _ = view.RetrieveData(httpClientRequestDuration.Name())
			if len(data) != 1 {
				t.Errorf("httpClientRequestDuration: received too many data rows: %d", len(data))
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpClientRequestDuration) {
				t.Errorf("httpClientRequestDuration: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpClientRequestDuration, data[0].String())
			}

			// httpClientRequestCount
			data, _ = view.RetrieveData(httpClientRequestCount.Name())
			if len(data) != 1 {
				t.Errorf("httpRequestCount: received too many data rows: %d", len(data))
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpClientRequestCount) {
				t.Errorf("httpRequestCount: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpClientRequestCount, data[0].String())
			}
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
