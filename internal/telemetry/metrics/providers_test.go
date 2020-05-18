package metrics

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func newEnvoyMetricsHandler() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
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

func getMetrics(t *testing.T) []byte {
	h, err := PrometheusHandler()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://test.local/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	b, _ := ioutil.ReadAll(resp.Body)

	if resp == nil || resp.StatusCode != 200 {
		t.Errorf("Metrics endpoint failed to respond: %s", b)
	}
	return b
}

func Test_PrometheusHandler(t *testing.T) {

	t.Run("no envoy", func(t *testing.T) {
		b := getMetrics(t)

		if m, _ := regexp.Match(`(?m)^# HELP .*`, b); !m {
			t.Errorf("Metrics endpoint did not contain any help messages: %s", b)
		}
	})

	t.Run("with envoy", func(t *testing.T) {
		fakeEnvoyMetricsServer := httptest.NewServer(newEnvoyMetricsHandler())
		envoyURL = fakeEnvoyMetricsServer.URL
		b := getMetrics(t)

		if m, _ := regexp.Match(`(?m)^go_.*`, b); !m {
			t.Errorf("Metrics endpoint did not contain internal metrics: %s", b)
		}
		if m, _ := regexp.Match(`(?m)^# TYPE envoy_.*`, b); !m {
			t.Errorf("Metrics endpoint did not contain envoy metrics: %s", b)
		}

	})

}
