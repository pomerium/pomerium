package clients

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/proto/authorize"
	mock "github.com/pomerium/pomerium/proto/authorize/mock_authorize"
)

func TestAuthorizeGRPC_Authorize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	client := mock.NewMockAuthorizerClient(ctrl)
	client.EXPECT().Authorize(
		gomock.Any(),
		gomock.Any(),
	).Return(&authorize.AuthorizeReply{IsValid: true}, nil).AnyTimes()

	tests := []struct {
		name    string
		route   string
		s       *sessions.State
		want    bool
		wantErr bool
	}{
		{"good", "hello.pomerium.io", &sessions.State{User: "admin@pomerium.io", Email: "admin@pomerium.io"}, true, false},
		{"impersonate request", "hello.pomerium.io", &sessions.State{User: "admin@pomerium.io", Email: "admin@pomerium.io", ImpersonateEmail: "other@other.example"}, true, false},
		{"session cannot be nil", "hello.pomerium.io", nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthorizeGRPC{client: client}
			got, err := a.Authorize(context.Background(), tt.route, tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizeGRPC.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AuthorizeGRPC.Authorize() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestAuthorizeGRPC_IsAdmin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	client := mock.NewMockAuthorizerClient(ctrl)
	client.EXPECT().IsAdmin(
		gomock.Any(),
		gomock.Any(),
	).Return(&authorize.IsAdminReply{IsAdmin: true}, nil).AnyTimes()

	tests := []struct {
		name    string
		s       *sessions.State
		want    bool
		wantErr bool
	}{
		{"good", &sessions.State{User: "admin@pomerium.io", Email: "admin@pomerium.io"}, true, false},
		{"session cannot be nil", nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthorizeGRPC{client: client}
			got, err := a.IsAdmin(context.Background(), tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizeGRPC.IsAdmin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AuthorizeGRPC.IsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
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
		{"no shared secret", &Options{}, true, "proxy/authenticator: grpc client requires shared secret", ""},
		{"empty connection", &Options{Addr: nil, SharedSecret: "shh"}, true, "proxy/authenticator: connection address required", ""},
		{"both internal and addr empty", &Options{Addr: nil, InternalAddr: nil, SharedSecret: "shh"}, true, "proxy/authenticator: connection address required", ""},
		{"addr with port", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:8443"}, SharedSecret: "shh"}, false, "", "localhost.example:8443"},
		{"addr without port", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example"}, SharedSecret: "shh"}, false, "", "localhost.example:443"},
		{"internal addr with port", &Options{Addr: nil, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example:8443"}, SharedSecret: "shh"}, false, "", "localhost.example:8443"},
		{"internal addr without port", &Options{Addr: nil, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example"}, SharedSecret: "shh"}, false, "", "localhost.example:443"},
		{"cert override", &Options{Addr: nil, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example"}, OverrideCertificateName: "*.local", SharedSecret: "shh"}, false, "", "localhost.example:443"},
		{"custom ca", &Options{Addr: nil, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example"}, OverrideCertificateName: "*.local", SharedSecret: "shh", CA: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURFVENDQWZrQ0ZBWHhneFg5K0hjWlBVVVBEK0laV0NGNUEvVTdNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1FVXgKQ3pBSkJnTlZCQVlUQWtGVk1STXdFUVlEVlFRSURBcFRiMjFsTFZOMFlYUmxNU0V3SHdZRFZRUUtEQmhKYm5SbApjbTVsZENCWGFXUm5hWFJ6SUZCMGVTQk1kR1F3SGhjTk1Ua3dNakk0TVRnMU1EQTNXaGNOTWprd01qSTFNVGcxCk1EQTNXakJGTVFzd0NRWURWUVFHRXdKQlZURVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVoTUI4R0ExVUUKQ2d3WVNXNTBaWEp1WlhRZ1YybGtaMmwwY3lCUWRIa2dUSFJrTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQwpBUThBTUlJQkNnS0NBUUVBOVRFMEFiaTdnMHhYeURkVUtEbDViNTBCT05ZVVVSc3F2THQrSWkwdlpjMzRRTHhOClJrT0hrOFZEVUgzcUt1N2UrNGVubUdLVVNUdzRPNFlkQktiSWRJTFpnb3o0YitNL3FVOG5adVpiN2pBVTdOYWkKajMzVDVrbXB3L2d4WHNNUzNzdUpXUE1EUDB3Z1BUZUVRK2J1bUxVWmpLdUVIaWNTL0l5dmtaVlBzRlE4NWlaUwpkNXE2a0ZGUUdjWnFXeFg0dlhDV25Sd3E3cHY3TThJd1RYc1pYSVRuNXB5Z3VTczNKb29GQkg5U3ZNTjRKU25GCmJMK0t6ekduMy9ScXFrTXpMN3FUdkMrNWxVT3UxUmNES21mZXBuVGVaN1IyVnJUQm42NndWMjVHRnBkSDIzN00KOXhJVkJrWEd1U2NvWHVPN1lDcWFrZkt6aXdoRTV4UmRaa3gweXdJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQQpBNElCQVFCaHRWUEI0OCs4eFZyVmRxM1BIY3k5QkxtVEtrRFl6N2Q0ODJzTG1HczBuVUdGSTFZUDdmaFJPV3ZxCktCTlpkNEI5MUpwU1NoRGUrMHpoNno4WG5Ha01mYnRSYWx0NHEwZ3lKdk9hUWhqQ3ZCcSswTFk5d2NLbXpFdnMKcTRiNUZ5NXNpRUZSekJLTmZtTGwxTTF2cW1hNmFCVnNYUUhPREdzYS83dE5MalZ2ay9PYm52cFg3UFhLa0E3cQpLMTQvV0tBRFBJWm9mb00xMzB4Q1RTYXVpeXROajlnWkx1WU9leEZhblVwNCt2MHBYWS81OFFSNTk2U0ROVTlKClJaeDhwTzBTaUYvZXkxVUZXbmpzdHBjbTQzTFVQKzFwU1hFeVhZOFJrRTI2QzNvdjNaTFNKc2pMbC90aXVqUlgKZUJPOWorWDdzS0R4amdtajBPbWdpVkpIM0YrUAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="}, false, "", "localhost.example:443"},
		{"bad ca encoding", &Options{Addr: nil, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example"}, OverrideCertificateName: "*.local", SharedSecret: "shh", CA: "^"}, true, "", "localhost.example:443"},
		{"custom ca file", &Options{Addr: nil, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example"}, OverrideCertificateName: "*.local", SharedSecret: "shh", CAFile: "testdata/example.crt"}, false, "", "localhost.example:443"},
		{"bad custom ca file", &Options{Addr: nil, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example"}, OverrideCertificateName: "*.local", SharedSecret: "shh", CAFile: "testdata/example.crt2"}, true, "", "localhost.example:443"},
		{"valid with insecure", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:8443"}, SharedSecret: "shh", WithInsecure: true}, false, "", "localhost.example:8443"},
		{"valid client round robin", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example:8443"}, SharedSecret: "shh", ClientDNSRoundRobin: true}, false, "", "dns:///localhost.example:8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewGRPCAuthorizeClient(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGRPCAuthorizeClient() error = %v, wantErr %v", err, tt.wantErr)
				if !strings.EqualFold(err.Error(), tt.wantErrStr) {
					t.Errorf("NewGRPCAuthorizeClient() error = %v did not contain wantErr %v", err, tt.wantErrStr)
				}
			}
			if got != nil && got.Conn.Target() != tt.wantTarget {
				t.Errorf("NewGRPCAuthorizeClient() target = %v expected %v", got.Conn.Target(), tt.wantTarget)

			}
		})
	}
}
