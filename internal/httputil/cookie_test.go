package httputil

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCookieChunker(t *testing.T) {
	t.Parallel()

	t.Run("chunk", func(t *testing.T) {
		t.Parallel()

		cc := NewCookieChunker(WithCookieChunkerChunkSize(16))
		srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			assert.NoError(t, cc.SetCookie(w, &http.Cookie{
				Name:  "example",
				Value: strings.Repeat("x", 77),
			}))
		}))
		defer srv1.Close()
		srv2 := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			cookie, err := cc.LoadCookie(r, "example")
			if assert.NoError(t, err) {
				assert.Equal(t, &http.Cookie{
					Name:  "example",
					Value: strings.Repeat("x", 77),
				}, cookie)
			}
		}))
		defer srv2.Close()

		jar, err := cookiejar.New(&cookiejar.Options{})
		client := &http.Client{Jar: jar}
		require.NoError(t, err)
		res, err := client.Get(srv1.URL)
		if assert.NoError(t, err) {
			assert.Equal(t, []string{
				"example=5",
				"example0=xxxxxxxxxxxxxxxx",
				"example1=xxxxxxxxxxxxxxxx",
				"example2=xxxxxxxxxxxxxxxx",
				"example3=xxxxxxxxxxxxxxxx",
				"example4=xxxxxxxxxxxxx",
			}, res.Header.Values("Set-Cookie"))
		}
		client.Get(srv2.URL)
	})

	t.Run("set max error", func(t *testing.T) {
		t.Parallel()

		cc := NewCookieChunker(WithCookieChunkerChunkSize(2), WithCookieChunkerMaxChunks(2))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			assert.Error(t, cc.SetCookie(w, &http.Cookie{
				Name:  "example",
				Value: strings.Repeat("x", 1024),
			}))
		}))
		defer srv.Close()
		http.Get(srv.URL)
	})

	t.Run("load max error", func(t *testing.T) {
		t.Parallel()

		cc1 := NewCookieChunker(WithCookieChunkerChunkSize(64))
		srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			assert.NoError(t, cc1.SetCookie(w, &http.Cookie{
				Name:  "example",
				Value: strings.Repeat("x", 1024),
			}))
		}))
		defer srv1.Close()

		cc2 := NewCookieChunker(WithCookieChunkerChunkSize(64), WithCookieChunkerMaxChunks(2))
		srv2 := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			cookie, err := cc2.LoadCookie(r, "example")
			assert.Error(t, err)
			assert.Nil(t, cookie)
		}))
		defer srv2.Close()

		jar, err := cookiejar.New(&cookiejar.Options{})
		require.NoError(t, err)
		client := &http.Client{Jar: jar}
		client.Get(srv1.URL)
		client.Get(srv2.URL)
	})
}
