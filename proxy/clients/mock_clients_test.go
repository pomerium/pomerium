package clients

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/pomerium/pomerium/internal/sessions"
)

func TestMockAuthenticate(t *testing.T) {
	// Absurd, but I caught a typo this way.
	redeemResponse := &sessions.SessionState{
		AccessToken:  "AccessToken",
		RefreshToken: "RefreshToken",
	}
	ma := &MockAuthenticate{
		RedeemError:    errors.New("RedeemError"),
		RedeemResponse: redeemResponse,
		RefreshResponse: &sessions.SessionState{
			AccessToken:  "AccessToken",
			RefreshToken: "RefreshToken",
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
