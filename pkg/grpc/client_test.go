package grpc

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func Test_grpcTimeoutInterceptor(t *testing.T) {
	mockInvoker := func(sleepTime time.Duration, wantFail bool) grpc.UnaryInvoker {
		return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			time.Sleep(sleepTime)
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("No deadline set")
			}

			now := time.Now()

			if ok && now.After(deadline) && !wantFail {
				t.Errorf("Deadline exceeded, but should not have.  now=%v, deadline=%v", now, deadline)
			} else if now.Before(deadline) && wantFail {
				t.Errorf("Deadline not exceeded, but should have.  now=%v, deadline=%v", now, deadline)
			}
			return nil
		}
	}

	timeOut := 300 * time.Millisecond
	to := grpcTimeoutInterceptor(timeOut)

	to(context.Background(), "test", nil, nil, nil, mockInvoker(timeOut*2, true))
	to(context.Background(), "test", nil, nil, nil, mockInvoker(timeOut/2, false))
}

func TestNewGRPC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		opts       *Options
		wantErr    bool
		wantErrStr string
		wantTarget string
	}{
		{"empty connection", &Options{Addr: nil}, true, "proxy/authenticator: connection address required", ""},
		{"both internal and addr empty", &Options{Addr: nil}, true, "proxy/authenticator: connection address required", ""},
		{"addr with port", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:8443"}}, false, "", "pomerium:///localhost.example:8443"},
		{"secure addr without port", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example"}}, false, "", "pomerium:///localhost.example:443"},
		{"insecure addr without port", &Options{Addr: &url.URL{Scheme: "http", Host: "localhost.example"}}, false, "", "pomerium:///localhost.example:80"},
		{"cert override", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:443"}, OverrideCertificateName: "*.local"}, false, "", "pomerium:///localhost.example:443"},
		{"custom ca", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:443"}, OverrideCertificateName: "*.local", CA: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURFVENDQWZrQ0ZBWHhneFg5K0hjWlBVVVBEK0laV0NGNUEvVTdNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1FVXgKQ3pBSkJnTlZCQVlUQWtGVk1STXdFUVlEVlFRSURBcFRiMjFsTFZOMFlYUmxNU0V3SHdZRFZRUUtEQmhKYm5SbApjbTVsZENCWGFXUm5hWFJ6SUZCMGVTQk1kR1F3SGhjTk1Ua3dNakk0TVRnMU1EQTNXaGNOTWprd01qSTFNVGcxCk1EQTNXakJGTVFzd0NRWURWUVFHRXdKQlZURVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVoTUI4R0ExVUUKQ2d3WVNXNTBaWEp1WlhRZ1YybGtaMmwwY3lCUWRIa2dUSFJrTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQwpBUThBTUlJQkNnS0NBUUVBOVRFMEFiaTdnMHhYeURkVUtEbDViNTBCT05ZVVVSc3F2THQrSWkwdlpjMzRRTHhOClJrT0hrOFZEVUgzcUt1N2UrNGVubUdLVVNUdzRPNFlkQktiSWRJTFpnb3o0YitNL3FVOG5adVpiN2pBVTdOYWkKajMzVDVrbXB3L2d4WHNNUzNzdUpXUE1EUDB3Z1BUZUVRK2J1bUxVWmpLdUVIaWNTL0l5dmtaVlBzRlE4NWlaUwpkNXE2a0ZGUUdjWnFXeFg0dlhDV25Sd3E3cHY3TThJd1RYc1pYSVRuNXB5Z3VTczNKb29GQkg5U3ZNTjRKU25GCmJMK0t6ekduMy9ScXFrTXpMN3FUdkMrNWxVT3UxUmNES21mZXBuVGVaN1IyVnJUQm42NndWMjVHRnBkSDIzN00KOXhJVkJrWEd1U2NvWHVPN1lDcWFrZkt6aXdoRTV4UmRaa3gweXdJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQQpBNElCQVFCaHRWUEI0OCs4eFZyVmRxM1BIY3k5QkxtVEtrRFl6N2Q0ODJzTG1HczBuVUdGSTFZUDdmaFJPV3ZxCktCTlpkNEI5MUpwU1NoRGUrMHpoNno4WG5Ha01mYnRSYWx0NHEwZ3lKdk9hUWhqQ3ZCcSswTFk5d2NLbXpFdnMKcTRiNUZ5NXNpRUZSekJLTmZtTGwxTTF2cW1hNmFCVnNYUUhPREdzYS83dE5MalZ2ay9PYm52cFg3UFhLa0E3cQpLMTQvV0tBRFBJWm9mb00xMzB4Q1RTYXVpeXROajlnWkx1WU9leEZhblVwNCt2MHBYWS81OFFSNTk2U0ROVTlKClJaeDhwTzBTaUYvZXkxVUZXbmpzdHBjbTQzTFVQKzFwU1hFeVhZOFJrRTI2QzNvdjNaTFNKc2pMbC90aXVqUlgKZUJPOWorWDdzS0R4amdtajBPbWdpVkpIM0YrUAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="}, false, "", "pomerium:///localhost.example:443"},
		{"bad ca encoding", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:443"}, OverrideCertificateName: "*.local", CA: "^"}, true, "", "pomerium:///localhost.example:443"},
		{"custom ca file", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:443"}, OverrideCertificateName: "*.local", CAFile: "testdata/example.crt"}, false, "", "pomerium:///localhost.example:443"},
		{"bad custom ca file", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:443"}, OverrideCertificateName: "*.local", CAFile: "testdata/example.crt2"}, true, "", "pomerium:///localhost.example:443"},
		{"valid with insecure", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:8443"}, WithInsecure: true}, false, "", "pomerium:///localhost.example:8443"},
		{"valid client round robin", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:8443"}, ClientDNSRoundRobin: true}, false, "", "pomerium:///localhost.example:8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewGRPCClientConn(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				if !strings.EqualFold(err.Error(), tt.wantErrStr) {
					t.Errorf("New() error = %v did not contain wantErr %v", err, tt.wantErrStr)
				}
			}
			if got != nil && got.Target() != tt.wantTarget {
				t.Errorf("New() target = %v expected %v", got.Target(), tt.wantTarget)
			}
		})
	}
}

func TestGetGRPC(t *testing.T) {
	cc1, err := GetGRPCClientConn("example", &Options{
		Addr: mustParseURL("https://localhost.example"),
	})
	if !assert.NoError(t, err) {
		return
	}

	cc2, err := GetGRPCClientConn("example", &Options{
		Addr: mustParseURL("https://localhost.example"),
	})
	if !assert.NoError(t, err) {
		return
	}

	assert.Same(t, cc1, cc2, "GetGRPCClientConn should return the same connection when there are no changes")

	cc3, err := GetGRPCClientConn("example", &Options{
		Addr:         mustParseURL("http://localhost.example"),
		WithInsecure: true,
	})
	if !assert.NoError(t, err) {
		return
	}

	assert.NotSame(t, cc1, cc3, "GetGRPCClientConn should return a new connection when there are changes")
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}
