package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCORS(t *testing.T) {
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
			Host string `json:"hostname"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "httpdetails.localhost.pomerium.io", result.Host,
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
			Host string `json:"hostname"`
		}
		err = json.NewDecoder(res.Body).Decode(&result)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotEqual(t, "httpdetails.localhost.pomerium.io", result.Host,
			"destination host should not be preserved in %v", result)
	})
}
