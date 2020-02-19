package grpc

import (
	"encoding/base64"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
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

	tests := []struct {
		name           string
		opt            *ServerOptions
		registrationFn func(s *grpc.Server)
		wg             *sync.WaitGroup
		wantNil        bool
		wantErr        bool
	}{
		{"simple", &ServerOptions{Addr: ":0"}, func(s *grpc.Server) {}, &sync.WaitGroup{}, false, false},
		{"simple keepalive options", &ServerOptions{Addr: ":0", KeepaliveParams: keepalive.ServerParameters{MaxConnectionAge: 5 * time.Minute}}, func(s *grpc.Server) {}, &sync.WaitGroup{}, false, false},
		{"bad tcp port", &ServerOptions{Addr: ":9999999"}, func(s *grpc.Server) {}, &sync.WaitGroup{}, true, true},
		{"with certs", &ServerOptions{Addr: ":0", TLSCertificate: certb64}, func(s *grpc.Server) {}, &sync.WaitGroup{}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewServer(tt.opt, tt.registrationFn, tt.wg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got == nil) != tt.wantNil {
				t.Errorf("NewServer() = %v, want %v", got, tt.wantNil)
			}
			if got != nil {
				// simulate a sigterm and cleanup the server
				c := make(chan os.Signal, 1)
				signal.Notify(c, syscall.SIGINT)
				defer signal.Stop(c)
				go Shutdown(got)
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
