package config

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetricsManager(t *testing.T) {
	li1, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	addr1 := li1.Addr().String()

	li2, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	addr2 := li2.Addr().String()

	li1.Close()
	li2.Close()

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
