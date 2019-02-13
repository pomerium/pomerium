package authenticator

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestMockAuthenticate(t *testing.T) {
	// Absurd, but I caught a typo this way.
	fixedDate := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	redeemResponse := &RedeemResponse{
		AccessToken:  "AccessToken",
		RefreshToken: "RefreshToken",
		Expiry:       fixedDate,
	}
	ma := &MockAuthenticate{
		RedeemError:      errors.New("RedeemError"),
		RedeemResponse:   redeemResponse,
		RefreshResponse:  "RefreshResponse",
		RefreshTime:      fixedDate,
		RefreshError:     errors.New("RefreshError"),
		ValidateResponse: true,
		ValidateError:    errors.New("ValidateError"),
		CloseError:       errors.New("CloseError"),
	}
	got, gotErr := ma.Redeem("a")
	if gotErr.Error() != "RedeemError" {
		t.Errorf("unexpected value for gotErr %s", gotErr)
	}
	if !reflect.DeepEqual(redeemResponse, got) {
		t.Errorf("unexpected value for redeemResponse %s", got)
	}
	gotToken, gotTime, gotErr := ma.Refresh("a")
	if gotErr.Error() != "RefreshError" {
		t.Errorf("unexpected value for gotErr %s", gotErr)
	}
	if !reflect.DeepEqual(gotToken, "RefreshResponse") {
		t.Errorf("unexpected value for gotToken %s", gotToken)
	}
	if !gotTime.Equal(fixedDate) {
		t.Errorf("unexpected value for gotTime %s", gotTime)
	}

	ok, gotErr := ma.Validate("a")
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
