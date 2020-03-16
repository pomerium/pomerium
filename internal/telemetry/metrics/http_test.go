package metrics

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pomerium/pomerium/internal/tripper"
	"go.opencensus.io/stats/view"
)

func testDataRetrieval(v *view.View, t *testing.T, want string) {
	if v == nil {
		t.Fatalf("%s: nil view passed", t.Name())
	}
	name := v.Name
	data, err := view.RetrieveData(name)

	if err != nil {
		t.Fatalf("%s: failed to retrieve data line %s", name, err)
	}

	if want != "" && len(data) != 1 {
		t.Fatalf("%s: received incorrect number of data rows: %d", name, len(data))
	}
	if want == "" && len(data) > 0 {
		t.Fatalf("%s: received incorrect number of data rows: %d", name, len(data))
	} else if want == "" {
		return
	}

	dataString := data[0].String()

	if want != "" && !strings.HasPrefix(dataString, want) {
		t.Errorf("%s: Found unexpected data row: \nwant: %s\ngot: %s\n", name, want, dataString)
	}
}

func newTestMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/good", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	})

	return mux
}

func Test_HTTPMetricsHandler(t *testing.T) {

	tests := []struct {
		name                          string
		url                           string
		verb                          string
		wanthttpServerRequestSize     string
		wanthttpServerResponseSize    string
		wanthttpServerRequestDuration string
		wanthttpServerRequestCount    string
	}{
		{
			name:                          "good get",
			url:                           "http://test.local/good",
			verb:                          "GET",
			wanthttpServerRequestSize:     "{ { {host test.local}{http_method GET}{service test_service} }&{1 0 5e-324 0 0 [1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerResponseSize:    "{ { {host test.local}{http.status 200}{http_method GET}{service test_service} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerRequestDuration: "{ { {host test.local}{http.status 200}{http_method GET}{service test_service} }&{1",
			wanthttpServerRequestCount:    "{ { {host test.local}{http.status 200}{http_method GET}{service test_service} }&{1",
		},
		{
			name:                          "good post",
			url:                           "http://test.local/good",
			verb:                          "POST",
			wanthttpServerRequestSize:     "{ { {host test.local}{http_method POST}{service test_service} }&{1 0 5e-324 0 0 [1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerResponseSize:    "{ { {host test.local}{http.status 200}{http_method POST}{service test_service} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerRequestDuration: "{ { {host test.local}{http.status 200}{http_method POST}{service test_service} }&{1",
			wanthttpServerRequestCount:    "{ { {host test.local}{http.status 200}{http_method POST}{service test_service} }&{1",
		},
		{
			name:                          "bad post",
			url:                           "http://test.local/bad",
			verb:                          "POST",
			wanthttpServerRequestSize:     "{ { {host test.local}{http_method POST}{service test_service} }&{1 0 5e-324 0 0 [1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerResponseSize:    "{ { {host test.local}{http.status 404}{http_method POST}{service test_service} }&{1 19 19 19 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpServerRequestDuration: "{ { {host test.local}{http.status 404}{http_method POST}{service test_service} }&{1",
			wanthttpServerRequestCount:    "{ { {host test.local}{http.status 404}{http_method POST}{service test_service} }&{1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view.Unregister(HTTPServerRequestCountView, HTTPServerRequestDurationView, HTTPServerRequestSizeView, HTTPServerResponseSizeView)
			view.Register(HTTPServerRequestCountView, HTTPServerRequestDurationView, HTTPServerRequestSizeView, HTTPServerResponseSizeView)

			req := httptest.NewRequest(tt.verb, tt.url, new(bytes.Buffer))
			rec := httptest.NewRecorder()

			h := HTTPMetricsHandler("test_service")(newTestMux())
			h.ServeHTTP(rec, req)

			testDataRetrieval(HTTPServerRequestSizeView, t, tt.wanthttpServerRequestSize)
			testDataRetrieval(HTTPServerResponseSizeView, t, tt.wanthttpServerResponseSize)
			testDataRetrieval(HTTPServerRequestDurationView, t, tt.wanthttpServerRequestDuration)
			testDataRetrieval(HTTPServerRequestCountView, t, tt.wanthttpServerRequestCount)
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
	chain := tripper.NewChain(HTTPMetricsRoundTripper("test_service", "test_destination"))
	rt := chain.Then(newTestTransport())
	client := http.Client{Transport: rt}

	tests := []struct {
		name                          string
		url                           string
		verb                          string
		wanthttpClientRequestSize     string
		wanthttpClientResponseSize    string
		wanthttpClientRequestDuration string
		wanthttpClientRequestCount    string
	}{
		{
			name:                          "good get",
			url:                           "http://test.local/good",
			verb:                          "GET",
			wanthttpClientRequestSize:     "{ { {destination test_destination}{host test.local}{http.status 200}{http_method GET}{service test_service} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientResponseSize:    "{ { {destination test_destination}{host test.local}{http.status 200}{http_method GET}{service test_service} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientRequestDuration: "{ { {destination test_destination}{host test.local}{http.status 200}{http_method GET}{service test_service} }&{1",
			wanthttpClientRequestCount:    "{ { {destination test_destination}{host test.local}{http.status 200}{http_method GET}{service test_service} }&{1",
		},
		{
			name:                          "good post",
			url:                           "http://test.local/good",
			verb:                          "POST",
			wanthttpClientRequestSize:     "{ { {destination test_destination}{host test.local}{http.status 200}{http_method POST}{service test_service} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientResponseSize:    "{ { {destination test_destination}{host test.local}{http.status 200}{http_method POST}{service test_service} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientRequestDuration: "{ { {destination test_destination}{host test.local}{http.status 200}{http_method POST}{service test_service} }&{1",
			wanthttpClientRequestCount:    "{ { {destination test_destination}{host test.local}{http.status 200}{http_method POST}{service test_service} }&{1",
		},
		{
			name:                          "bad post",
			url:                           "http://test.local/bad",
			verb:                          "POST",
			wanthttpClientRequestSize:     "{ { {destination test_destination}{host test.local}{http.status 404}{http_method POST}{service test_service} }&{1 19 19 19 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientResponseSize:    "{ { {destination test_destination}{host test.local}{http.status 404}{http_method POST}{service test_service} }&{1 19 19 19 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpClientRequestDuration: "{ { {destination test_destination}{host test.local}{http.status 404}{http_method POST}{service test_service} }&{1",
			wanthttpClientRequestCount:    "{ { {destination test_destination}{host test.local}{http.status 404}{http_method POST}{service test_service} }&{1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view.Unregister(HTTPClientRequestCountView, HTTPClientRequestDurationView, HTTPClientResponseSizeView, HTTPClientRequestSizeView)
			view.Register(HTTPClientRequestCountView, HTTPClientRequestDurationView, HTTPClientResponseSizeView, HTTPClientRequestSizeView)

			req, _ := http.NewRequest(tt.verb, tt.url, new(bytes.Buffer))
			resp, err := client.Do(req)
			// must be done to record()
			ioutil.ReadAll(resp.Body)

			t.Logf("response: %#v, %#v\n\n", resp, err)
			testDataRetrieval(HTTPClientRequestSizeView, t, tt.wanthttpClientRequestSize)
			testDataRetrieval(HTTPClientResponseSizeView, t, tt.wanthttpClientResponseSize)
			testDataRetrieval(HTTPClientRequestDurationView, t, tt.wanthttpClientRequestDuration)
			testDataRetrieval(HTTPClientRequestCountView, t, tt.wanthttpClientRequestCount)
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
