package config

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsManager(t *testing.T) {
	ctx := t.Context()
	src := NewStaticSource(&Config{
		Options: &Options{
			MetricsAddr: "ADDRESS",
		},
	})
	mgr := NewMetricsManager(ctx, src)
	srv1 := httptest.NewServer(mgr)
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "ERROR", http.StatusInternalServerError)
	}))
	defer srv2.Close()

	getStatusCode := func(addr string) int {
		res, err := http.Get(fmt.Sprintf("%s/metrics", addr))
		require.NoError(t, err)
		return res.StatusCode
	}

	assert.Equal(t, 200, getStatusCode(srv1.URL))
	assert.Equal(t, 500, getStatusCode(srv2.URL))
}

func TestMetricsManagerBasicAuth(t *testing.T) {
	src := NewStaticSource(&Config{
		Options: &Options{
			MetricsAddr:      "ADDRESS",
			MetricsBasicAuth: base64.StdEncoding.EncodeToString([]byte("x:y")),
		},
	})
	mgr := NewMetricsManager(t.Context(), src)
	srv1 := httptest.NewServer(mgr)
	defer srv1.Close()

	res, err := http.Get(fmt.Sprintf("%s/metrics", srv1.URL))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/metrics", srv1.URL), nil)
	require.NoError(t, err)
	req.SetBasicAuth("x", "y")
	res, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}
