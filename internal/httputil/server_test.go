package httputil

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
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
	"github.com/pomerium/pomerium/internal/cryptutil"
)

const privKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMQiDy26/R4ca/OdnjIf8OEDeHcw8yB5SDV9FD500CW5oAoGCCqGSM49
AwEHoUQDQgAEFumdSrEe9dnPEUU3LuyC8l6MM6PefNgpSsRL4GrD22XITMjqDKFr
jqJTf0Fo1ZWm4v+Eds6s88rsLzEC+cKLRQ==
-----END EC PRIVATE KEY-----`
const pubKey = `-----BEGIN CERTIFICATE-----
MIIBeDCCAR+gAwIBAgIUUGE8w2S7XzpkVLbNq5QUxyVOwqEwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGdW51c2VkMCAXDTE5MDcxNTIzNDQyOVoYDzQ3NTcwNjExMjM0
NDI5WjARMQ8wDQYDVQQDDAZ1bnVzZWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQW6Z1KsR712c8RRTcu7ILyXowzo9582ClKxEvgasPbZchMyOoMoWuOolN/QWjV
labi/4R2zqzzyuwvMQL5wotFo1MwUTAdBgNVHQ4EFgQURYdcaniRqBHXeaM79LtV
pyJ4EwAwHwYDVR0jBBgwFoAURYdcaniRqBHXeaM79LtVpyJ4EwAwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBHbhVnGbwXqaMZ1dB8eBAK56jyeWDZ
2PWXmFMTu7+RywIgaZ7UwVNB2k7KjEEBiLm0PIRcpJmczI2cP9+ZMIkPHHw=
-----END CERTIFICATE-----`

func TestNewServer(t *testing.T) {
	certb64, err := cryptutil.CertifcateFromBase64(
		base64.StdEncoding.EncodeToString([]byte(pubKey)),
		base64.StdEncoding.EncodeToString([]byte(privKey)))
	if err != nil {
		t.Fatal(err)
	}
	t.Parallel()
	tests := []struct {
		name        string
		opt         *ServerOptions
		httpHandler http.Handler
		// want        *http.Server
		wantErr bool
	}{

		{"good basic http handler",
			&ServerOptions{
				Addr:           "127.0.0.1:0",
				TLSCertificate: certb64,
			},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			false},
		// todo(bdd): fails travis-ci
		// {"good no address",
		// 	&ServerOptions{
		// 		TLSCertificate: certb64,
		// 	},
		// 	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 		fmt.Fprintln(w, "Hello, http")
		// 	}),
		// 	false},
		// todo(bdd): fails travis-ci
		// {"empty handler",
		// nil,
		// http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 	fmt.Fprintln(w, "Hello, http")
		// }),
		// false},
		{"bad port - invalid port range ",
			&ServerOptions{
				Addr:           "127.0.0.1:65536",
				TLSCertificate: certb64,
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			true},
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
				greeting, err := ioutil.ReadAll(res.Body)
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
	tests := []struct {
		name       string
		wantStatus int
		wantBody   string
	}{
		{"http://example", http.StatusMovedPermanently, "<a href=\"https://example\">Moved Permanently</a>.\n\n"},
		{"http://example:8080", http.StatusMovedPermanently, "<a href=\"https://example\">Moved Permanently</a>.\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example/", nil)
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
