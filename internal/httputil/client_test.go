package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

func TestDefaultClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range []string{"X-B3-Sampled", "X-B3-Spanid", "X-B3-Traceid", "X-Request-Id"} {
			if _, ok := r.Header[header]; !ok {
				t.Errorf("header %s is not set", header)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req = req.WithContext(requestid.WithValue(t.Context(), "foo"))
	_, _ = getDefaultClient().Do(req)
}
