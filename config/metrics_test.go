package config

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetricsManager(t *testing.T) {
	addr1, addr2 := "127.0.1.1:19999", "127.0.2.1:19999"

	src := NewStaticSource(&Config{
		Options: &Options{
			MetricsAddr: addr1,
		},
	})
	mgr := NewMetricsManager(src)
	defer mgr.Close()

	getStatusCode := func(addr string) int {
		res, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
		if err != nil {
			return 500
		}
		defer res.Body.Close()
		return res.StatusCode
	}

	assert.Equal(t, 200, getStatusCode(addr1))
	assert.Equal(t, 500, getStatusCode(addr2))

	src.SetConfig(&Config{
		Options: &Options{
			MetricsAddr: addr2,
		},
	})

	assert.Equal(t, 500, getStatusCode(addr1))
	assert.Equal(t, 200, getStatusCode(addr2))
}
