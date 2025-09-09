package health

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCLI(t *testing.T) {
	assert := assert.New(t)
	mgr := NewManager()
	c1, c2, c3 := Check("check1"), Check("check2"), Check("check3")
	hP := NewHTTPProvider(mgr, WithExpectedChecks(c1, c2, c3))
	status := http.HandlerFunc(hP.Status)
	server := httptest.NewServer(status)

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/status", nil)
	type testcase struct {
		filter Filter
		err    error
	}
	tcs1 := []testcase{
		{
			err: ErrUnhealthy,
			filter: Filter{
				Exclude: []Check{},
			},
		},
		{
			err: nil,
			filter: Filter{
				Exclude: []Check{c3},
			},
		},
	}
	mgr.ReportStatus(c1, StatusRunning)
	mgr.ReportStatus(c2, StatusRunning)
	mgr.ReportError(c3, fmt.Errorf("some error"))
	for _, tc := range tcs1 {
		_, err := getHTTPStatus(server.Client(), req, tc.filter)
		if err != nil {
			assert.True(errors.Is(err, ErrUnhealthy))
			assert.ErrorIs(err, tc.err)
		} else {
			assert.Nil(tc.err, "expected an error but got nonde")
		}

	}

	mgr.ReportStatus(c1, StatusTerminating)
	_, err := getHTTPStatus(server.Client(), req, Filter{
		Exclude: []Check{c3},
	})
	assert.ErrorIs(err, ErrUnhealthy)
}
