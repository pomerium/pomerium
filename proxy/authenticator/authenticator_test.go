package authenticator

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/sessions"
)

func TestMockAuthenticate(t *testing.T) {
	// Absurd, but I caught a typo this way.
	fixedDate := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	redeemResponse := &sessions.SessionState{
		AccessToken:      "AccessToken",
		RefreshToken:     "RefreshToken",
		LifetimeDeadline: fixedDate,
	}
	ma := &MockAuthenticate{
		RedeemError:    errors.New("RedeemError"),
		RedeemResponse: redeemResponse,
		RefreshResponse: &sessions.SessionState{
			AccessToken:      "AccessToken",
			RefreshToken:     "RefreshToken",
			LifetimeDeadline: fixedDate,
		},
		RefreshError:     errors.New("RefreshError"),
		ValidateResponse: true,
		ValidateError:    errors.New("ValidateError"),
		CloseError:       errors.New("CloseError"),
	}
	got, gotErr := ma.Redeem(context.Background(), "a")
	if gotErr.Error() != "RedeemError" {
		t.Errorf("unexpected value for gotErr %s", gotErr)
	}
	if !reflect.DeepEqual(redeemResponse, got) {
		t.Errorf("unexpected value for redeemResponse %s", got)
	}
	newSession, gotErr := ma.Refresh(context.Background(), nil)
	if gotErr.Error() != "RefreshError" {
		t.Errorf("unexpected value for gotErr %s", gotErr)
	}
	if !reflect.DeepEqual(newSession, redeemResponse) {
		t.Errorf("unexpected value for newSession %s", newSession)
	}

	ok, gotErr := ma.Validate(context.Background(), "a")
	if !ok {
		t.Errorf("unexpected value for ok : %t", ok)
	}
	if gotErr.Error() != "ValidateError" {
		t.Errorf("unexpected value for gotErr %s", gotErr)
	}
	gotErr = ma.Close()
	if gotErr.Error() != "CloseError" {
		t.Errorf("unexpected value for ma.CloseError %s", gotErr)
	}

}

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		opts        *Options
		wantErr     bool
	}{
		{"grpc good", "grpc", &Options{Addr: "test", InternalAddr: "intranet.local", SharedSecret: "secret"}, false},
		{"grpc missing shared secret", "grpc", &Options{Addr: "test", InternalAddr: "intranet.local", SharedSecret: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.serviceName, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
