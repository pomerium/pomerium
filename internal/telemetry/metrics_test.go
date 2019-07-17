package telemetry

import (
	"bytes"
	"io/ioutil"
	"net/http/httptest"
	"regexp"
	"testing"
)

func Test_PrometheusHandler(t *testing.T) {
	h, err := PrometheusHandler()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://test.local/metrics", new(bytes.Buffer))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	b, _ := ioutil.ReadAll(resp.Body)

	if resp == nil || resp.StatusCode != 200 {
		t.Errorf("Metrics endpoint failed to respond: %s", b)
	}

	if m, _ := regexp.Match("^# HELP .*", b); !m {
		t.Errorf("Metrics endpoint did not contain any help messages: %s", b)
	}
}
