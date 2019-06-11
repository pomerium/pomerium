package metrics

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pomerium/pomerium/internal/middleware"
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
		name                    string
		url                     string
		verb                    string
		wanthttpResponseSize    string
		wanthttpRequestDuration string
		wanthttpRequestCount    string
	}{
		{
			name:                    "good get",
			url:                     "http://test.local/good",
			verb:                    "GET",
			wanthttpResponseSize:    "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpRequestDuration: "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1",
			wanthttpRequestCount:    "{ { {host test.local}{method GET}{service test_service}{status 200} }&{1",
		},
		{
			name:                    "good post",
			url:                     "http://test.local/good",
			verb:                    "POST",
			wanthttpResponseSize:    "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1 5 5 5 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpRequestDuration: "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1",
			wanthttpRequestCount:    "{ { {host test.local}{method POST}{service test_service}{status 200} }&{1",
		},
		{
			name:                    "bad post",
			url:                     "http://test.local/bad",
			verb:                    "POST",
			wanthttpResponseSize:    "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1 19 19 19 0 [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
			wanthttpRequestDuration: "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1",
			wanthttpRequestCount:    "{ { {host test.local}{method POST}{service test_service}{status 404} }&{1",
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
			data, _ := view.RetrieveData(httpResponseSize.Name())
			if len(data) != 1 {
				t.Errorf("httpResponseSize: received wrong number of data rows: %d", len(data))
				return
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpResponseSize) {
				t.Errorf("httpResponseSize: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpResponseSize, data[0].String())
			}

			// httpResponseSize
			data, _ = view.RetrieveData(httpRequestDuration.Name())
			if len(data) != 1 {
				t.Errorf("httpRequestDuration: received too many data rows: %d", len(data))
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpRequestDuration) {
				t.Errorf("httpRequestDuration: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpRequestDuration, data[0].String())
			}

			// httpRequestCount
			data, _ = view.RetrieveData(httpRequestCount.Name())
			if len(data) != 1 {
				t.Errorf("httpRequestCount: received too many data rows: %d", len(data))
			}

			if !strings.HasPrefix(data[0].String(), tt.wanthttpRequestCount) {
				t.Errorf("httpRequestCount: Found unexpected data row: \nwant: %s\ngot: %s\n", tt.wanthttpRequestCount, data[0].String())
			}
		})
	}
}
