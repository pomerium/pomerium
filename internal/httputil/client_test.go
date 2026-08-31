package httputil

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

func TestDefaultClient(t *testing.T) {
	t.Parallel()

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

func TestNewResponseSizeLimitedClient(t *testing.T) {
	t.Parallel()

	serve := func(size int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte("x"), size))
		}))
	}

	cases := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "under", size: 9},
		{name: "exact", size: 10},
		{name: "over", size: 11, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := serve(tc.size)
			t.Cleanup(srv.Close)

			res, err := NewSizeLimitClient(srv.Client(), 10).Get(srv.URL)
			require.NoError(t, err)
			defer res.Body.Close()

			body, err := io.ReadAll(res.Body)
			if tc.wantErr {
				assert.ErrorIs(t, err, ErrResponseTooLarge)
				return
			}
			require.NoError(t, err)
			assert.Len(t, body, tc.size)
		})
	}
}
