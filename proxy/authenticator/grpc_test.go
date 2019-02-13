package authenticator

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	pb "github.com/pomerium/pomerium/proto/authenticate"
	mock "github.com/pomerium/pomerium/proto/authenticate/mock_authenticate"
)

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
	).Return(&pb.AuthenticateReply{
		AccessToken:  "mocked access token",
		RefreshToken: "mocked refresh token",
		IdToken:      "mocked id token",
		User:         "user1",
		Email:        "test@email.com",
		Expiry:       mockExpire,
	}, nil)
	tests := []struct {
		name    string
		idToken string
		want    *RedeemResponse
		wantErr bool
	}{
		{"good", "unit_test", &RedeemResponse{
			AccessToken:  "mocked access token",
			RefreshToken: "mocked refresh token",
			IDToken:      "mocked id token",
			User:         "user1",
			Email:        "test@email.com",
			Expiry:       (fixedDate),
		}, false},
		{"empty code", "", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AuthenticateGRPC{client: mockAuthenticateClient}
			got, err := a.Redeem(tt.idToken)
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

			got, err := a.Validate(tt.idToken)
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
	req := &pb.RefreshRequest{RefreshToken: "unit_test"}
	mockExpire, err := ptypes.TimestampProto(fixedDate)
	if err != nil {
		t.Fatalf("%v failed converting timestamp", err)
	}
	mockRefreshClient.EXPECT().Refresh(
		gomock.Any(),
		&rpcMsg{msg: req},
	).Return(&pb.RefreshReply{
		AccessToken: "mocked access token",
		Expiry:      mockExpire,
	}, nil).AnyTimes()

	tests := []struct {
		name         string
		refreshToken string
		wantAT       string
		wantExp      time.Time
		wantErr      bool
	}{
		{"good", "unit_test", "mocked access token", fixedDate, false},
		{"missing refresh", "", "", time.Time{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AuthenticateGRPC{client: mockRefreshClient}

			got, gotExp, err := a.Refresh(tt.refreshToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("Proxy.AuthenticateRefresh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantAT {
				t.Errorf("Proxy.AuthenticateRefresh() got = %v, want %v", got, tt.wantAT)
			}
			if !reflect.DeepEqual(gotExp, tt.wantExp) {
				t.Errorf("Proxy.AuthenticateRefresh() gotExp = %v, want %v", gotExp, tt.wantExp)
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
	}{
		{"no shared secret", &Options{}, true, "proxy/authenticator: grpc client requires shared secret"},
		{"empty connection", &Options{Addr: "", SharedSecret: "shh"}, true, "proxy/authenticator: connection address required"},
		{"empty connections", &Options{Addr: "", InternalAddr: "", SharedSecret: "shh"}, true, "proxy/authenticator: connection address required"},
		{"internal addr", &Options{Addr: "", InternalAddr: "intranet.local", SharedSecret: "shh"}, false, "proxy/authenticator: connection address required"},
		{"cert overide", &Options{Addr: "", InternalAddr: "intranet.local", OverideCertificateName: "*.local", SharedSecret: "shh"}, false, "proxy/authenticator: connection address required"},

		// {"addr and internal ", &Options{Addr: "localhost", InternalAddr: "local.localhost", SharedSecret: "shh"}, nil, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGRPC(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGRPC() error = %v, wantErr %v", err, tt.wantErr)
				if !strings.EqualFold(err.Error(), tt.wantErrStr) {
					t.Errorf("NewGRPC() error = %v did not contain wantErr %v", err, tt.wantErrStr)
				}

				return

			}
		})
	}
}
