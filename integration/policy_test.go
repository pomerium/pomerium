package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/integration/flows"
	"github.com/pomerium/pomerium/internal/httputil"
)

func TestCORS(t *testing.T) {
	if ClusterType == "traefik" || ClusterType == "nginx" {
		t.Skip()
		return
	}

	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "OPTIONS", "https://httpdetails.localhost.pomerium.io/cors-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Origin", "https://httpdetails.localhost.pomerium.io")

		res, err := getClient().Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode, "unexpected status code")
	})
	t.Run("disabled", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "OPTIONS", "https://httpdetails.localhost.pomerium.io/cors-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Origin", "https://httpdetails.localhost.pomerium.io")

		res, err := getClient().Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		assert.NotEqual(t, http.StatusOK, res.StatusCode, "unexpected status code")
	})
}

func TestPreserveHostHeader(t *testing.T) {
	if ClusterType == "traefik" || ClusterType == "nginx" {
		t.Skip()
		return
	}

	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	t.Run("enabled", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/preserve-host-header-enabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := getClient().Do(req)
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
		req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/preserve-host-header-disabled", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := getClient().Do(req)
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
	if ClusterType == "traefik" || ClusterType == "nginx" {
		t.Skip()
		return
	}

	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
	defer clearTimeout()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := getClient().Do(req)
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

	req, err := http.NewRequestWithContext(ctx, "GET", "https://httpdetails.localhost.pomerium.io/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("X-Custom-Request-Header-To-Remove", "foo")

	res, err := getClient().Do(req)
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
	if ClusterType == "traefik" || ClusterType == "nginx" {
		t.Skip()
		return
	}

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

	req, err := http.NewRequestWithContext(ctx, "GET", "https://cloudrun.localhost.pomerium.io/", nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := getClient().Do(req)
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
	if ClusterType == "traefik" || ClusterType == "nginx" {
		t.Skip()
		return
	}

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Minute*10)
	defer clearTimeout()

	getDistribution := func(t *testing.T, path string) map[string]float64 {
		client := getClient()
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
			req, err := http.NewRequestWithContext(ctx, "GET",
				"https://httpdetails.localhost.pomerium.io/"+path, nil)
			if !assert.NoError(t, err) {
				return distribution
			}

			res, err = client.Do(req)
			if !assert.NoError(t, err) {
				return distribution
			}

			var result struct {
				Hostname string `json:"hostname"`
			}
			err = json.NewDecoder(res.Body).Decode(&result)
			_ = res.Body.Close()
			assert.NoError(t, err)
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
	if ClusterType == "traefik" || ClusterType == "nginx" {
		t.Skip()
		return
	}

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Minute*10)
	defer clearTimeout()

	t.Run("no client cert", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "GET",
			"https://client-cert-required.localhost.pomerium.io/", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := getClient().Do(req)
		if assert.Error(t, err, "expected error when no certificate provided") {
			assert.Contains(t, err.Error(), "remote error: tls: certificate required")
		} else {
			res.Body.Close()
		}
	})
	t.Run("untrusted client cert", func(t *testing.T) {
		// Configure an http.Client with an untrusted client certificate.
		cert := loadCertificate(t, "downstream-2-client")
		client := *getClient()
		tr := client.Transport.(*http.Transport).Clone()
		// We need to use the GetClientCertificate callback here in order to
		// present a certificate that doesn't match the advertised CA.
		tr.TLSClientConfig.GetClientCertificate =
			func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
		client.Transport = tr

		req, err := http.NewRequestWithContext(ctx, "GET",
			"https://client-cert-required.localhost.pomerium.io/", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if assert.Error(t, err, "expected error for untrusted certificate") {
			assert.Contains(t, err.Error(), "remote error: tls: unknown certificate authority")
		} else {
			res.Body.Close()
		}
	})
	t.Run("valid client cert", func(t *testing.T) {
		// Configure an http.Client with a trusted client certificate.
		cert := loadCertificate(t, "downstream-1-client")
		client := *getClient()
		tr := client.Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
		client.Transport = tr

		res, err := flows.Authenticate(ctx, &client,
			mustParseURL("https://client-cert-required.localhost.pomerium.io/"),
			flows.WithEmail("user1@dogs.test"))
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
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
	if ClusterType == "traefik" || ClusterType == "nginx" {
		t.Skip()
		return
	}

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Minute*10)
	defer clearTimeout()

	// Initializes a new http.Client with the given certificate.
	newClientWithCert := func(certName string) *http.Client {
		cert := loadCertificate(t, certName)
		client := *getClient()
		tr := client.Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
		client.Transport = tr
		return &client
	}

	// Asserts that we get a successful JSON response from the httpdetails
	// service, matching the given path.
	assertOK := func(res *http.Response, err error, path string) {
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()

		var result struct {
			Path string `json:"path"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, path, result.Path)
	}

	t.Run("cert1", func(t *testing.T) {
		client := newClientWithCert("downstream-1-client")

		// With cert1, we should get a valid response for the /ca1 path.
		res, err := flows.Authenticate(ctx, client,
			mustParseURL("https://client-cert-overlap.localhost.pomerium.io/ca1"),
			flows.WithEmail("user1@dogs.test"))
		assertOK(res, err, "/ca1")

		// With cert1, we should get an HTTP error response for the /ca2 path.
		req, err := http.NewRequestWithContext(ctx, "GET",
			"https://client-cert-overlap.localhost.pomerium.io/ca2", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err = client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()
		assert.Equal(t, httputil.StatusInvalidClientCertificate, res.StatusCode)
	})
	t.Run("cert2", func(t *testing.T) {
		client := newClientWithCert("downstream-2-client")

		// With cert2, we should get an HTTP error response for the /ca1 path.
		req, err := http.NewRequestWithContext(ctx, "GET",
			"https://client-cert-overlap.localhost.pomerium.io/ca1", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if !assert.NoError(t, err, "unexpected http error") {
			return
		}
		defer res.Body.Close()
		assert.Equal(t, httputil.StatusInvalidClientCertificate, res.StatusCode)

		// With cert2, we should get a valid response for the /ca2 path.
		res, err = flows.Authenticate(ctx, client,
			mustParseURL("https://client-cert-overlap.localhost.pomerium.io/ca2"),
			flows.WithEmail("user1@dogs.test"))
		assertOK(res, err, "/ca2")
	})
	t.Run("no cert", func(t *testing.T) {
		// Without a client certificate, connections should be rejected
		req, err := http.NewRequestWithContext(ctx, "GET",
			"https://client-cert-overlap.localhost.pomerium.io/ca1", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := getClient().Do(req)
		if assert.Error(t, err, "expected error when no certificate provided") {
			assert.Contains(t, err.Error(), "remote error: tls: certificate required")
		} else {
			res.Body.Close()
		}

		req, err = http.NewRequestWithContext(ctx, "GET",
			"https://client-cert-overlap.localhost.pomerium.io/ca2", nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err = getClient().Do(req)
		if assert.Error(t, err, "expected error when no certificate provided") {
			assert.Contains(t, err.Error(), "remote error: tls: certificate required")
		} else {
			res.Body.Close()
		}
	})
}
