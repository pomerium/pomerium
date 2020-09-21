package autocert

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
)

func TestRedirect(t *testing.T) {
	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	addr := li.Addr().String()
	_ = li.Close()

	src := config.NewStaticSource(&config.Config{
		Options: &config.Options{
			HTTPRedirectAddr: addr,
			Headers: map[string]string{
				"X-Frame-Options":           "SAMEORIGIN",
				"X-XSS-Protection":          "1; mode=block",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
			},
		},
	})
	_, err = New(src)
	if !assert.NoError(t, err) {
		return
	}
	err = waitFor(addr)
	if !assert.NoError(t, err) {
		return
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res, err := client.Get(fmt.Sprintf("http://%s", addr))
	if !assert.NoError(t, err) {
		return
	}
	defer res.Body.Close()

	assert.Equal(t, http.StatusMovedPermanently, res.StatusCode, "should redirect to https")
	for k, v := range src.GetConfig().Options.Headers {
		assert.Equal(t, v, res.Header.Get(k), "should add header")
	}
}

func waitFor(addr string) error {
	var err error
	deadline := time.Now().Add(time.Second * 30)
	for time.Now().Before(deadline) {
		var conn net.Conn
		conn, err = net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}
