package health_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/health"
)

func expectHTTPCode(t *testing.T, code int, handlers ...http.Handler) {
	if len(handlers) == 0 {
		panic("no handlers provided")
	}
	get := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, handler := range handlers {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, get)
		assert.Equal(t, code, rec.Code)
	}
}

func TestHTTPStatus(t *testing.T) {
	assert := assert.New(t)
	mgr := health.NewManager()

	hP := health.NewHTTPProvider(mgr, health.WithExpectedChecks(health.Check("c1")))
	mgr.Register(health.ProviderHTTP, mgr)

	// get := httptest.NewRequest(http.MethodGet, "/", nil)
	status := http.HandlerFunc(hP.Status)

	methods := []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	}

	for _, method := range methods {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/", nil)
		status.ServeHTTP(rec, req)
		assert.Equal(rec.Result().StatusCode, http.StatusMethodNotAllowed)
	}

	check1, check2, check3 := health.Check("A"), health.Check("B"), health.Check("C")
	rec := httptest.NewRecorder()

	mgr.ReportStatus(check1, health.StatusRunning)
	mgr.ReportStatus(check2, health.StatusTerminating)
	mgr.ReportError(check3, fmt.Errorf("some error"))

	expected := `{
  "statuses": {
    "A": {
      "status": "RUNNING"
    },
    "B": {
      "status": "TERMINATING"
    },
    "C": {
      "status": "UNKNOWN",
      "error": "some error"
    }
  },
  "checks": [
    "c1"
  ]
}`

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	status.ServeHTTP(rec, req)
	assert.Equal(http.StatusOK, rec.Result().StatusCode)

	dataResp, err := io.ReadAll(rec.Result().Body)
	assert.NoError(err)
	assert.Equal(expected, string(dataResp))
}

func TestHTTP(t *testing.T) {
	mgr := health.NewManager()
	check1, check2, check3 := health.Check("A"), health.Check("B"), health.Check("C")

	hP := health.NewHTTPProvider(
		mgr,
		health.WithExpectedChecks(
			check1,
			check2,
			check3,
		),
	)

	mgr.Register(health.ProviderHTTP, hP)

	startup := http.HandlerFunc(hP.StartupProbe)
	ready := http.HandlerFunc(hP.ReadyProbe)
	live := http.HandlerFunc(hP.LivenessProbe)

	expectHTTPCode(t, 503, startup, ready, live)

	mgr.ReportStatus(check1, health.StatusRunning)
	mgr.ReportStatus(check2, health.StatusRunning)
	expectHTTPCode(t, 503, startup, ready, live)

	mgr.ReportStatus(check3, health.StatusRunning)
	expectHTTPCode(t, 200, startup, ready, live)

	mgr.ReportError(check2, errors.New("err2"))
	expectHTTPCode(t, 200, startup)
	expectHTTPCode(t, 503, ready, live)

	mgr.ReportStatus(check2, health.StatusRunning)
	expectHTTPCode(t, 200, startup, ready, live)

	mgr.ReportStatus(check1, health.StatusTerminating)
	expectHTTPCode(t, 200, startup, live)
	expectHTTPCode(t, 503, ready)

	mgr.ReportStatus(check2, health.StatusTerminating)
	mgr.ReportStatus(check3, health.StatusTerminating)
	expectHTTPCode(t, 200, startup, live)
	expectHTTPCode(t, 503, ready)

	mgr.ReportError(check3, errors.New("err3"))
	expectHTTPCode(t, 200, startup)
	expectHTTPCode(t, 503, ready, live)

	rec := httptest.NewRecorder()
	startup.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Result().StatusCode)
}
