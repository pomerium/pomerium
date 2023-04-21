package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/integration/flows"
)

func TestQueryStringParams(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	qs := url.Values{
		"q1": {"a&b&c"},
		"q2": {"x?y?z"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpdetails.localhost.pomerium.io/?"+qs.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := getClient(t).Do(req)
	if !assert.NoError(t, err, "unexpected http error") {
		return
	}
	defer res.Body.Close()

	var result struct {
		Query map[string]string
	}
	err = json.NewDecoder(res.Body).Decode(&result)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, map[string]string{
		"q1": "a&b&c",
		"q2": "x?y?z",
	}, result.Query,
		"expected custom request header to be sent upstream")
}

func TestCORS(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, "https://httpdetails.localhost.pomerium.io/cors-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		req.Header.Set("Origin", "https://httpdetails.localhost.pomerium.io")

		res, err := getClient(t).Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode, "unexpected status code")
	})
	t.Run("disabled", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, "https://httpdetails.localhost.pomerium.io/cors-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		req.Header.Set("Origin", "https://httpdetails.localhost.pomerium.io")

		res, err := getClient(t).Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.NotEqual(t, http.StatusOK, res.StatusCode, "unexpected status code")
	})
}

func TestPreserveHostHeader(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpdetails.localhost.pomerium.io/preserve-host-header-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := getClient(t).Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		var result struct {
			Headers struct {
				Host string `json:"host"`
			} `json:"headers"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "httpdetails.localhost.pomerium.io", result.Headers.Host,
			"destination host should be preserved in %v", result)
	})
	t.Run("disabled", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpdetails.localhost.pomerium.io/preserve-host-header-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := getClient(t).Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		var result struct {
			Headers struct {
				Host string `json:"host"`
			} `json:"headers"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotEqual(t, "httpdetails.localhost.pomerium.io", result.Headers.Host,
			"destination host should not be preserved in %v", result)
	})
}

func TestSetRequestHeaders(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpdetails.localhost.pomerium.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := getClient(t).Do(req)
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

func TestRemoveRequestHeaders(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpdetails.localhost.pomerium.io/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Custom-Request-Header-To-Remove", "foo")

	res, err := getClient(t).Do(req)
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

	_, exist := result.Headers["X-Custom-Request-Header-To-Remove"]
	assert.False(t, exist, "expected X-Custom-Request-Header-To-Remove not to be present.")
}

func TestWebsocket(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("disabled", func(t *testing.T) {
		ws, _, err := (&websocket.Dialer{
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

func TestGoogleCloudRun(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudrun.localhost.pomerium.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := getClient(t).Do(req)
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

	if result.Headers["x-idp"] == "google" {
		assert.NotEmpty(t, result.Headers["authorization"], "expected authorization header when cloudrun is enabled")
	}
}

func TestLoadBalancer(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Minute*10)
	defer clearTimeout()

	getDistribution := func(t *testing.T, path string) map[string]float64 {
		client := getClient(t)
		distribution := map[string]float64{}

		res, err := flows.Authenticate(ctx, client,
			mustParseURL("https://httpdetails.localhost.pomerium.io/"+path),
			flows.WithEmail("user1@dogs.test"))
		if !assert.NoError(t, err) {
			return distribution
		}
		_, _ = io.ReadAll(res.Body)
		_ = res.Body.Close()

		for i := 0; i < 100; i++ {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				"https://httpdetails.localhost.pomerium.io/"+path, nil)
			if !assert.NoError(t, err) {
				return distribution
			}

			res, err = client.Do(req)
			if !assert.NoError(t, err) {
				return distribution
			}
			defer res.Body.Close()

			bs, err := io.ReadAll(res.Body)
			if !assert.NoError(t, err) {
				return distribution
			}

			var result struct {
				Hostname string `json:"hostname"`
			}
			err = json.Unmarshal(bs, &result)
			if !assert.NoError(t, err, "invalid json: %s", bs) {
				return distribution
			}
			distribution[result.Hostname]++
		}

		return distribution
	}

	t.Run("round robin", func(t *testing.T) {
		distribution := getDistribution(t, "round-robin")
		var xs []float64
		for _, x := range distribution {
			xs = append(xs, x)
		}
		assert.Lessf(t, standardDeviation(xs), 10.0, "should distribute requests evenly, got: %v",
			distribution)
	})

	t.Run("ring hash", func(t *testing.T) {
		distribution := getDistribution(t, "ring-hash")
		assert.Lenf(t, distribution, 1, "should distribute requests to a single backend, got: %v",
			distribution)
	})

	t.Run("maglev", func(t *testing.T) {
		distribution := getDistribution(t, "maglev")
		assert.Lenf(t, distribution, 1, "should distribute requests to a single backend, got: %v",
			distribution)
	})
}
