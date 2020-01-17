package client

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pomerium/pomerium/internal/grpc/authorize"
	"github.com/pomerium/pomerium/internal/grpc/authorize/client/mock_authorize"
	"github.com/pomerium/pomerium/internal/sessions"
)

func TestClient_Authorize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	client := mock_authorize.NewMockAuthorizerClient(ctrl)
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
			a := &Client{client: client}
			got, err := a.Authorize(context.Background(), tt.route, tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Client.Authorize() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestClient_IsAdmin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	client := mock_authorize.NewMockAuthorizerClient(ctrl)
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
			a := &Client{client: client}
			got, err := a.IsAdmin(context.Background(), tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.IsAdmin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Client.IsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}
