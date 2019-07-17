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
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestNewTLSServer(t *testing.T) {
	cmpopts.IgnoreFields(http.Server{}, "TLSConfig")

	tests := []struct {
		name        string
		opt         *ServerOptions
		httpHandler http.Handler
		grpcHandler http.Handler
		// want        *http.Server
		wantErr bool
	}{
		{"simple good",
			&ServerOptions{
				Addr: "127.0.0.1:9999",
				Cert: base64.StdEncoding.EncodeToString([]byte(pubKey)),
				Key:  base64.StdEncoding.EncodeToString([]byte(privKey)),
			},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			nil,
			false},
		{"simple grpc",
			&ServerOptions{
				Addr: "127.0.0.1:9999",
				Cert: base64.StdEncoding.EncodeToString([]byte(pubKey)),
				Key:  base64.StdEncoding.EncodeToString([]byte(privKey)),
			},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, grpc")
			}),
			false},
		{"good with cert files",
			&ServerOptions{
				Addr:     "127.0.0.1:9999",
				CertFile: "test_data/cert.pem",
				KeyFile:  "test_data/privkey.pem",
			},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, grpc")
			}),
			false},
		{"unreadable cert file",
			&ServerOptions{
				Addr:     "127.0.0.1:9999",
				CertFile: "test_data",
				KeyFile:  "test_data/privkey.pem",
			},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, grpc")
			}),
			true},
		{"unreadable key file",
			&ServerOptions{
				Addr:     "127.0.0.1:9999",
				CertFile: "./test_data/cert.pem",
				KeyFile:  "./test_data",
			},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, grpc")
			}),
			true},
		{"unreadable key file",
			&ServerOptions{
				Addr:     "127.0.0.1:9999",
				CertFile: "./test_data/cert.pem",
				KeyFile:  "./test_data/file-does-not-exist",
			},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, grpc")
			}),
			true},
		{"bad private key base64",
			&ServerOptions{
				Addr: "127.0.0.1:9999",
				Cert: base64.StdEncoding.EncodeToString([]byte(pubKey)),
				Key:  "bad guy",
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			nil,
			true},
		{"bad public key base64",
			&ServerOptions{
				Addr: "127.0.0.1:9999",
				Key:  base64.StdEncoding.EncodeToString([]byte(pubKey)),
				Cert: "bad guy",
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			nil,
			true},
		{"bad port - invalid port range ",
			&ServerOptions{
				Addr: "127.0.0.1:65536",
				Cert: base64.StdEncoding.EncodeToString([]byte(pubKey)),
				Key:  base64.StdEncoding.EncodeToString([]byte(privKey)),
			}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			nil,
			true},
		{"nil apply default but will fail",
			nil,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			nil,
			true},
		{"empty, apply defaults to missing",
			&ServerOptions{},
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "Hello, http")
			}),
			nil,
			true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := NewTLSServer(tt.opt, tt.httpHandler, tt.grpcHandler)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTLSServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				// we cheat a little bit here and use the httptest server to test the client
				ts := httptest.NewTLSServer(srv.Handler)
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
