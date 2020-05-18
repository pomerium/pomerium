package sessions

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestState_Impersonating(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		Email              string
		Groups             []string
		ImpersonateEmail   string
		ImpersonateGroups  []string
		want               bool
		wantResponseEmail  string
		wantResponseGroups string
	}{
		{"impersonating", "actual@user.com", []string{"actual-group"}, "impersonating@user.com", []string{"impersonating-group"}, true, "impersonating@user.com", "impersonating-group"},
		{"not impersonating", "actual@user.com", []string{"actual-group"}, "", []string{}, false, "actual@user.com", "actual-group"},
		{"impersonating user only", "actual@user.com", []string{"actual-group"}, "impersonating@user.com", []string{}, true, "impersonating@user.com", "actual-group"},
		{"impersonating group only", "actual@user.com", []string{"actual-group"}, "", []string{"impersonating-group"}, true, "actual@user.com", "impersonating-group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{
				Email:  tt.Email,
				Groups: tt.Groups,
			}
			s.SetImpersonation(tt.ImpersonateEmail, strings.Join(tt.ImpersonateGroups, ","))
			if got := s.Impersonating(); got != tt.want {
				t.Errorf("State.Impersonating() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestState_IsExpired(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		Audience    jwt.Audience
		Expiry      *jwt.NumericDate
		NotBefore   *jwt.NumericDate
		IssuedAt    *jwt.NumericDate
		AccessToken *oauth2.Token

		audience string
		wantErr  bool
	}{
		{"good", []string{"a", "b", "c"}, jwt.NewNumericDate(time.Now().Add(time.Hour)), jwt.NewNumericDate(time.Now().Add(-time.Hour)), jwt.NewNumericDate(time.Now().Add(-time.Hour)), &oauth2.Token{Expiry: time.Now().Add(time.Hour)}, "a", false},
		{"bad expiry", []string{"a", "b", "c"}, jwt.NewNumericDate(time.Now().Add(-time.Hour)), jwt.NewNumericDate(time.Now().Add(-time.Hour)), jwt.NewNumericDate(time.Now().Add(-time.Hour)), &oauth2.Token{Expiry: time.Now().Add(time.Hour)}, "a", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{
				Audience:  tt.Audience,
				Expiry:    tt.Expiry,
				NotBefore: tt.NotBefore,
				IssuedAt:  tt.IssuedAt,
			}
			if exp := s.IsExpired(); exp != tt.wantErr {
				t.Errorf("State.IsExpired() error = %v, wantErr %v", exp, tt.wantErr)
			}
		})
	}
}
