package httputil

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestNewServer(t *testing.T) {
	// to support envs that won't let us use 443 without root
	defaultServerOptions.Addr = ":0"

	tests := []struct {
		name        string
		opt         *ServerOptions
		httpHandler http.Handler
		// want        *http.Server
		wantErr bool
	}{
		{
			"good basic http handler",
			&ServerOptions{
				Addr:     ":0",
				Insecure: true,
			},
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			false,
		},
		{
			"bad neither insecure nor certs set",
			&ServerOptions{
				Addr: ":0",
			},
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			true,
		},
		{
			"good no address",
			&ServerOptions{
				Insecure: true,
			},
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			false,
		},
		{
			"empty handler",
			nil,
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			true,
		},
		{
			"bad port - invalid port range ",
			&ServerOptions{
				Addr:     ":65536",
				Insecure: true,
			}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			true,
		},
		{
			"good tls set",
			&ServerOptions{
				TLSConfig: &tls.Config{},
			},
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			srv, err := NewServer(tt.opt, tt.httpHandler, &wg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				// we cheat a little bit here and use the httptest server to test the client
				ts := httptest.NewServer(srv.Handler)
				defer ts.Close()
				client := ts.Client()
				res, err := client.Get(ts.URL)
				if err != nil {
					log.Fatal(err)
				}
				greeting, err := io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%s", greeting)
			}
			if srv != nil {
				// simulate a sigterm and cleanup the server
				c := make(chan os.Signal, 1)
				signal.Notify(c, syscall.SIGINT)
				defer signal.Stop(c)
				go Shutdown(srv)
				syscall.Kill(syscall.Getpid(), syscall.SIGINT)
				waitSig(t, c, syscall.SIGINT)
			}
		})
	}
}

func waitSig(t *testing.T, c <-chan os.Signal, sig os.Signal) {
	select {
	case s := <-c:
		if s != sig {
			t.Fatalf("signal was %v, want %v", s, sig)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for %v", sig)
	}
}

func TestRedirectHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		url        string
		wantStatus int
		wantBody   string
	}{
		{"http://example", http.StatusMovedPermanently, "<a href=\"https://example\">Moved Permanently</a>.\n\n"},
		{"http://example:8080", http.StatusMovedPermanently, "<a href=\"https://example\">Moved Permanently</a>.\n\n"},
		{"http://example:8080/some/path?x=y", http.StatusMovedPermanently, "<a href=\"https://example/some/path?x=y\">Moved Permanently</a>.\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			rr := httptest.NewRecorder()
			RedirectHandler().ServeHTTP(rr, req)
			if diff := cmp.Diff(tt.wantStatus, rr.Code); diff != "" {
				t.Errorf("TestRedirectHandler() code diff :%s", diff)
			}
			if diff := cmp.Diff(tt.wantBody, rr.Body.String()); diff != "" {
				t.Errorf("TestRedirectHandler() body diff :%s", diff)
			}
		})
	}
}
