package httputil

import (
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSizeLimitClientLargeMaxSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(srv.Close)

	c := NewSizeLimitClient(srv.Client(), math.MaxInt64)
	assert.NotPanics(t, func() {
		resp, err := c.Get(srv.URL)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
	}, "a maxSize near math.MaxInt64 must not overflow the slice bound")
}
