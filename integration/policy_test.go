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
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/integration/flows"
	"github.com/pomerium/pomerium/internal/httputil"
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

func TestDownstreamClientCA(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Minute*10)
	defer clearTimeout()

	t.Run("no client cert", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://client-cert-required.localhost.pomerium.io/", nil)
		require.NoError(t, err)

		res, err := getClient(t).Do(req)
		require.NoError(t, err)
		res.Body.Close()
		assert.Equal(t, httputil.StatusInvalidClientCertificate, res.StatusCode)
	})
	t.Run("untrusted client cert", func(t *testing.T) {
		// Configure an http.Client with an untrusted client certificate.
		cert := loadCertificate(t, "downstream-2-client")
		client, transport := getClientWithTransport(t)
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://client-cert-required.localhost.pomerium.io/", nil)
		require.NoError(t, err)

		res, err := client.Do(req)
		require.NoError(t, err)
		res.Body.Close()
		assert.Equal(t, httputil.StatusInvalidClientCertificate, res.StatusCode)
	})
	t.Run("valid client cert", func(t *testing.T) {
		// Configure an http.Client with a trusted client certificate.
		cert := loadCertificate(t, "downstream-1-client")
		client, transport := getClientWithTransport(t)
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}

		res, err := flows.Authenticate(ctx, client,
			mustParseURL("https://client-cert-required.localhost.pomerium.io/"),
			flows.WithEmail("user1@dogs.test"))
		require.NoError(t, err)
		defer res.Body.Close()

		var result struct {
			Path string `json:"path"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, "/", result.Path)
	})
}

func TestMultipleDownstreamClientCAs(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Minute*10)
	defer clearTimeout()

	// Initializes a new http.Client with the given certificate.
	newClientWithCert := func(certName string) *http.Client {
		cert := loadCertificate(t, certName)
		client, transport := getClientWithTransport(t)
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		return client
	}

	// Asserts that we get a successful JSON response from the httpdetails
	// service, matching the given path.
	assertOK := func(t *testing.T, res *http.Response, err error, path string) {
		require.NoError(t, err, "unexpected http error")
		defer res.Body.Close()

		var result struct {
			Path string `json:"path"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		require.NoError(t, err)
		assert.Equal(t, path, result.Path)
	}

	t.Run("cert1", func(t *testing.T) {
		client := newClientWithCert("downstream-1-client")

		// With cert1, we should get a valid response for the /ca1 path
		// (after login).
		res, err := flows.Authenticate(ctx, client,
			mustParseURL("https://client-cert-overlap.localhost.pomerium.io/ca1"),
			flows.WithEmail("user1@dogs.test"))
		assertOK(t, res, err, "/ca1")

		// With cert1, we should get an HTML error page for the /ca2 path.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://client-cert-overlap.localhost.pomerium.io/ca2", nil)
		require.NoError(t, err)
		res, err = client.Do(req)
		require.NoError(t, err, "unexpected http error")
		res.Body.Close()
		assert.Equal(t, httputil.StatusInvalidClientCertificate, res.StatusCode)
	})
	t.Run("cert2", func(t *testing.T) {
		client := newClientWithCert("downstream-2-client")

		// With cert2, we should get an HTML error page for the /ca1 path
		// (before login).
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://client-cert-overlap.localhost.pomerium.io/ca1", nil)
		require.NoError(t, err)
		res, err := client.Do(req)
		require.NoError(t, err, "unexpected http error")
		res.Body.Close()
		assert.Equal(t, httputil.StatusInvalidClientCertificate, res.StatusCode)

		// With cert2, we should get a valid response for the /ca2 path
		// (after login).
		res, err = flows.Authenticate(ctx, client,
			mustParseURL("https://client-cert-overlap.localhost.pomerium.io/ca2"),
			flows.WithEmail("user1@dogs.test"))
		assertOK(t, res, err, "/ca2")
	})
	t.Run("no cert", func(t *testing.T) {
		client := getClient(t)

		// Without a client certificate, both paths should return an HTML error
		// page (no login redirect).
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://client-cert-overlap.localhost.pomerium.io/ca1", nil)
		require.NoError(t, err)
		res, err := client.Do(req)
		require.NoError(t, err, "unexpected http error")
		res.Body.Close()
		assert.Equal(t, httputil.StatusInvalidClientCertificate, res.StatusCode)

		req, err = http.NewRequestWithContext(ctx, http.MethodGet,
			"https://client-cert-overlap.localhost.pomerium.io/ca2", nil)
		require.NoError(t, err)
		res, err = client.Do(req)
		require.NoError(t, err, "unexpected http error")
		res.Body.Close()
		assert.Equal(t, httputil.StatusInvalidClientCertificate, res.StatusCode)
	})
}