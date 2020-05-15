package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
			Host string `json:"host"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "httpdetails.localhost.pomerium.io", result.Host,
			"destination host should be preserved in %v", result)
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
			Host string `json:"host"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotEqual(t, "httpdetails.localhost.pomerium.io", result.Host,
			"destination host should not be preserved in %v", result)
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

	assert.Equal(t, "custom-request-header-value", result.Headers["X-Custom-Request-Header"],
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

func TestTLSSkipVerify(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/tls-skip-verify-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
	t.Run("disabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/tls-skip-verify-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	})
}

func TestTLSServerName(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/tls-server-name-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
	t.Run("disabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/tls-server-name-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	})
}

func TestTLSCustomCA(t *testing.T) {
	ctx := mainCtx
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/tls-custom-ca-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)
	})
	t.Run("disabled", func(t *testing.T) {
		client := testcluster.NewHTTPClient()

		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/tls-custom-ca-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	})
}
