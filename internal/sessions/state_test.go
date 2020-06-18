package sessions

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestState_Impersonating(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		ImpersonateEmail   string
		ImpersonateGroups  []string
		want               bool
		wantResponseEmail  string
		wantResponseGroups string
	}{
		{"impersonating", "impersonating@user.com", []string{"impersonating-group"}, true, "impersonating@user.com", "impersonating-group"},
		{"not impersonating", "", []string{}, false, "actual@user.com", "actual-group"},
		{"impersonating user only", "impersonating@user.com", []string{}, true, "impersonating@user.com", "actual-group"},
		{"impersonating group only", "", []string{"impersonating-group"}, true, "actual@user.com", "impersonating-group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{}
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

func TestState_UnmarshalJSON(t *testing.T) {
	fixedTime := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	timeNow = func() time.Time {
		return fixedTime
	}
	defer func() { timeNow = time.Now }()
	tests := []struct {
		name    string
		in      *State
		want    State
		wantErr bool
	}{
		{
			"good",
			&State{ID: "xyz"},
			State{ID: "xyz", NotBefore: jwt.NewNumericDate(fixedTime), IssuedAt: jwt.NewNumericDate(fixedTime)},
			false,
		},
		{
			"with user",
			&State{ID: "xyz"},
			State{ID: "xyz", NotBefore: jwt.NewNumericDate(fixedTime), IssuedAt: jwt.NewNumericDate(fixedTime)},
			false,
		},
		{
			"without",
			&State{ID: "xyz", Subject: "user"},
			State{ID: "xyz", Subject: "user", NotBefore: jwt.NewNumericDate(fixedTime), IssuedAt: jwt.NewNumericDate(fixedTime)},
			false,
		},
		{
			"missing id",
			&State{},
			State{NotBefore: jwt.NewNumericDate(fixedTime), IssuedAt: jwt.NewNumericDate(fixedTime)},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatal(err)
			}

			s := NewSession(&State{}, "", nil)
			if err := s.UnmarshalJSON(data); (err != nil) != tt.wantErr {
				t.Errorf("State.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, s); diff != "" {
				t.Errorf("State.UnmarshalJSON() error = %v", diff)
			}
		})
	}
}
