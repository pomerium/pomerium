package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pomerium/pomerium/integration/internal/netutil"
	"github.com/stretchr/testify/assert"
)

func TestCORS(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "OPTIONS", "https://httpdetails.localhost.pomerium.io/cors-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Origin", "https://httpdetails.localhost.pomerium.io")

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode, "unexpected status code")
	})
	t.Run("disabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "OPTIONS", "https://httpdetails.localhost.pomerium.io/cors-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Origin", "https://httpdetails.localhost.pomerium.io")

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.NotEqual(t, http.StatusOK, res.StatusCode, "unexpected status code")
	})
}

func TestPreserveHostHeader(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/preserve-host-header-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		var result struct {
			Headers map[string]string `json:"headers"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "httpdetails.localhost.pomerium.io", result.Headers["host"],
			"destination host should be preserved")
	})
	t.Run("disabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/preserve-host-header-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		var result struct {
			Headers map[string]string `json:"headers"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotEqual(t, "httpdetails.localhost.pomerium.io", result.Headers["host"],
			"destination host should not be preserved")
	})

}

func TestSetRequestHeaders(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	client := testcluster.NewHTTPClient()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if !assert.NoError(t, err, "unexpected http error") {
		return
	}
	defer res.Body.Close()

	var result struct {
		Headers map[string]string `json:"headers"`
	}
	err = json.NewDecoder(res.Body).Decode(&result)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "custom-request-header-value", result.Headers["x-custom-request-header"],
		"expected custom request header to be sent upstream")

}

func TestWebsocket(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("disabled", func(t *testing.T) {
		ws, _, err := (&websocket.Dialer{
			NetDialContext: testcluster.Transport.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}).DialContext(ctx, "wss://disabled-ws-echo.localhost.pomerium.io", nil)
		if !assert.Error(t, err, "expected bad handshake when websocket is not enabled") {
			ws.Close()
			return
		}
	})
	t.Run("enabled", func(t *testing.T) {
		ws, _, err := (&websocket.Dialer{
			NetDialContext: testcluster.Transport.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}).DialContext(ctx, "wss://enabled-ws-echo.localhost.pomerium.io", nil)
		if !assert.NoError(t, err, "expected no error when creating websocket") {
			return
		}
		defer ws.Close()

		msg := "hello world"
		err = ws.WriteJSON("hello world")
		assert.NoError(t, err, "expected no error when writing json to websocket")
		err = ws.ReadJSON(&msg)
		assert.NoError(t, err, "expected no error when reading json from websocket")
	})
}

func TestSNIMismatch(t *testing.T) {
	// Browsers will coalesce connections for the same IP address and TLS certificate
	// even if the request was made to different domain names. We need to support this
	// so this test makes a request with an incorrect TLS server name to make sure it
	// gets routed properly

	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	hostport, err := testcluster.GetNodePortAddr(ctx, "default", "pomerium-proxy-nodeport")
	if err != nil {
		t.Fatal(err)
	}

	client := testcluster.NewHTTPClientWithTransport(&http.Transport{
		DialContext: netutil.NewLocalDialer((&net.Dialer{}), map[string]string{
			"443": hostport,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			ServerName: "ws-echo.localhost.pomerium.io",
		},
	})

	req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/ping", nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.Do(req)
	if !assert.NoError(t, err, "unexpected http error") {
		return
	}
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)
}
