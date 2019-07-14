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
		RedeemError:    errors.New("redeem error"),
		RedeemResponse: redeemResponse,
		RefreshResponse: &sessions.SessionState{
			AccessToken:  "AccessToken",
			RefreshToken: "RefreshToken",
		},
		RefreshError:     errors.New("refresh error"),
		ValidateResponse: true,
		ValidateError:    errors.New("validate error"),
		CloseError:       errors.New("close error"),
	}
	got, gotErr := ma.Redeem(context.Background(), "a")
	if gotErr.Error() != "redeem error" {
		t.Errorf("unexpected value for gotErr %s", gotErr)
	}
	if !reflect.DeepEqual(redeemResponse, got) {
		t.Errorf("unexpected value for redeemResponse %s", got)
	}
	newSession, gotErr := ma.Refresh(context.Background(), nil)
	if gotErr.Error() != "refresh error" {
		t.Errorf("unexpected value for gotErr %s", gotErr)
	}
	if !reflect.DeepEqual(newSession, redeemResponse) {
		t.Errorf("unexpected value for newSession %s", newSession)
	}

	ok, gotErr := ma.Validate(context.Background(), "a")
	if !ok {
		t.Errorf("unexpected value for ok : %t", ok)
	}
	if gotErr.Error() != "validate error" {
		t.Errorf("unexpected value for gotErr %s", gotErr)
	}
	gotErr = ma.Close()
	if gotErr.Error() != "close error" {
		t.Errorf("unexpected value for ma.CloseError %s", gotErr)
	}

}
