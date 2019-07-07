package clients // import "github.com/pomerium/pomerium/proxy/clients"

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authenticate"
	mock "github.com/pomerium/pomerium/proto/authenticate/mock_authenticate"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		opts        *Options
		wantErr     bool
	}{
		{"grpc good", "grpc", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example"}, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example"}, SharedSecret: "secret"}, false},
		{"grpc missing shared secret", "grpc", &Options{Addr: &url.URL{Scheme: "https", Host: "localhost.example"}, InternalAddr: &url.URL{Scheme: "https", Host: "localhost.example"}, SharedSecret: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthenticateClient(tt.serviceName, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var fixedDate = time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)

// rpcMsg implements the gomock.Matcher interface
type rpcMsg struct {
	msg proto.Message
}

func (r *rpcMsg) Matches(msg interface{}) bool {
	m, ok := msg.(proto.Message)
	if !ok {
		return false
	}
	return proto.Equal(m, r.msg)
}

func (r *rpcMsg) String() string {
	return fmt.Sprintf("is %s", r.msg)
}

func TestProxy_Redeem(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAuthenticateClient := mock.NewMockAuthenticatorClient(ctrl)
	req := &pb.AuthenticateRequest{Code: "unit_test"}
	mockExpire, err := ptypes.TimestampProto(fixedDate)
	if err != nil {
		t.Fatalf("%v failed converting timestamp", err)
	}

	mockAuthenticateClient.EXPECT().Authenticate(
		gomock.Any(),
		&rpcMsg{msg: req},
	).Return(&pb.Session{
		AccessToken:     "mocked access token",
		RefreshToken:    "mocked refresh token",
		IdToken:         "mocked id token",
		User:            "user1",
		Email:           "test@email.com",
		RefreshDeadline: mockExpire,
	}, nil)
	tests := []struct {
		name    string
		idToken string
		want    *sessions.SessionState
		wantErr bool
	}{
		{"good", "unit_test", &sessions.SessionState{
			AccessToken:     "mocked access token",
			RefreshToken:    "mocked refresh token",
			IDToken:         "mocked id token",
			User:            "user1",
			Email:           "test@email.com",
			RefreshDeadline: (fixedDate),
		}, false},
		{"empty code", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AuthenticateGRPC{client: mockAuthenticateClient}
			got, err := a.Redeem(context.Background(), tt.idToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("Proxy.AuthenticateValidate() error = %v,\n wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				if got.AccessToken != "mocked access token" {
					t.Errorf("authenticate: invalid access token")
				}
				if got.RefreshToken != "mocked refresh token" {
					t.Errorf("authenticate: invalid refresh token")
				}
				if got.IDToken != "mocked id token" {
					t.Errorf("authenticate: invalid id token")
				}
				if got.User != "user1" {
					t.Errorf("authenticate: invalid user")
				}
				if got.Email != "test@email.com" {
					t.Errorf("authenticate: invalid email")
				}
			}
		})
	}
}
func TestProxy_AuthenticateValidate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAuthenticateClient := mock.NewMockAuthenticatorClient(ctrl)
	req := &pb.ValidateRequest{IdToken: "unit_test"}

	mockAuthenticateClient.EXPECT().Validate(
		gomock.Any(),
		&rpcMsg{msg: req},
	).Return(&pb.ValidateReply{IsValid: false}, nil)

	ac := mockAuthenticateClient
	tests := []struct {
		name    string
		idToken string
		want    bool
		wantErr bool
	}{
		{"good", "unit_test", false, false},
		{"empty id token", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AuthenticateGRPC{client: ac}

			got, err := a.Validate(context.Background(), tt.idToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("Proxy.AuthenticateValidate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Proxy.AuthenticateValidate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_AuthenticateRefresh(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRefreshClient := mock.NewMockAuthenticatorClient(ctrl)
	mockExpire, _ := ptypes.TimestampProto(fixedDate)

	mockRefreshClient.EXPECT().Refresh(
		gomock.Any(),
		gomock.Not(sessions.SessionState{RefreshToken: "fail"}),
	).Return(&pb.Session{
		AccessToken:     "new access token",
		RefreshDeadline: mockExpire,
	}, nil).AnyTimes()

	tests := []struct {
		name    string
		session *sessions.SessionState
		want    *sessions.SessionState
		wantErr bool
	}{
		{"good",
			&sessions.SessionState{RefreshToken: "unit_test"},
			&sessions.SessionState{
				AccessToken:     "new access token",
				RefreshDeadline: fixedDate,
			}, false},
		{"empty refresh token", &sessions.SessionState{RefreshToken: ""}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AuthenticateGRPC{client: mockRefreshClient}

			got, err := a.Refresh(context.Background(), tt.session)
			if (err != nil) != tt.wantErr {
				t.Errorf("Proxy.AuthenticateRefresh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Proxy.AuthenticateRefresh() got = \n%#v\nwant \n%#v", got, tt.want)
			}
		})
	}
}

func TestNewGRPC(t *testing.T) {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewGRPCAuthenticateClient(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGRPCAuthenticateClient() error = %v, wantErr %v", err, tt.wantErr)
				if !strings.EqualFold(err.Error(), tt.wantErrStr) {
					t.Errorf("NewGRPCAuthenticateClient() error = %v did not contain wantErr %v", err, tt.wantErrStr)
				}
			}
			if got != nil && got.Conn.Target() != tt.wantTarget {
				t.Errorf("NewGRPCAuthenticateClient() target = %v expected %v", got.Conn.Target(), tt.wantTarget)

			}
		})
	}
}
