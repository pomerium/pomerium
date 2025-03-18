package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"
)

func newEnvoyMetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`
# TYPE envoy_server_initialization_time_ms histogram
envoy_server_initialization_time_ms_bucket{le="0.5"} 0
envoy_server_initialization_time_ms_bucket{le="1"} 0
envoy_server_initialization_time_ms_bucket{le="5"} 0
envoy_server_initialization_time_ms_bucket{le="10"} 0
envoy_server_initialization_time_ms_bucket{le="25"} 0
envoy_server_initialization_time_ms_bucket{le="50"} 0
envoy_server_initialization_time_ms_bucket{le="100"} 0
envoy_server_initialization_time_ms_bucket{le="250"} 0
envoy_server_initialization_time_ms_bucket{le="500"} 1
envoy_server_initialization_time_ms_bucket{le="1000"} 1
`))
	}
}

func getMetrics(t *testing.T, envoyURL *url.URL, header http.Header) []byte {
	h, err := PrometheusHandler([]ScrapeEndpoint{{Name: "envoy", URL: *envoyURL}}, time.Second*20, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://test.local/metrics", nil)
	if header != nil {
		req.Header = header
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	b, _ := io.ReadAll(resp.Body)

	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Errorf("Metrics endpoint failed to respond: %s", b)
	}
	return b
}

func Test_PrometheusHandler(t *testing.T) {
	t.Run("no envoy", func(t *testing.T) {
		b := getMetrics(t, &url.URL{}, nil)

		if m, _ := regexp.Match(`(?m)^# HELP .*`, b); !m {
			t.Errorf("Metrics endpoint did not contain any help messages: %s", b)
		}
	})

	t.Run("with envoy", func(t *testing.T) {
		fakeEnvoyMetricsServer := httptest.NewServer(newEnvoyMetricsHandler())
		envoyURL, _ := url.Parse(fakeEnvoyMetricsServer.URL)
		b := getMetrics(t, envoyURL, nil)

		if m, _ := regexp.Match(`(?m)^go_.*`, b); !m {
			t.Errorf("Metrics endpoint did not contain internal metrics: %s", b)
		}
		if m, _ := regexp.Match(`(?m)^# TYPE envoy_.*`, b); !m {
			t.Errorf("Metrics endpoint did not contain envoy metrics: %s", b)
		}
	})

	t.Run("with envoy, request protobuf format", func(t *testing.T) {
		fakeEnvoyMetricsServer := httptest.NewServer(newEnvoyMetricsHandler())
		envoyURL, _ := url.Parse(fakeEnvoyMetricsServer.URL)
		header := http.Header{}
		header.Set("Accept", "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited")
		b := getMetrics(t, envoyURL, header)

		if m, _ := regexp.Match(`(?m)^go_.*`, b); !m {
			t.Errorf("Metrics endpoint did not contain internal metrics: %s", b)
		}
		if m, _ := regexp.Match(`(?m)^# TYPE envoy_.*`, b); !m {
			t.Errorf("Metrics endpoint did not contain envoy metrics: %s", b)
		}
	})
}
