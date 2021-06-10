package sessions

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/oauth2"
)

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

func TestVersion_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		jsonStr     string
		wantVersion string
		wantErr     bool
	}{
		{"Version is string", `"1"`, "1", false},
		{"Version is integer", `1`, "1", false},
		{"Version is float", `1.1`, "1.1", false},
		{"Invalid version", `[1]`, "", true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var v Version
			if err := v.UnmarshalJSON([]byte(tc.jsonStr)); (err != nil) != tc.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && v.String() != tc.wantVersion {
				t.Errorf("mismatch version, want: %s, got: %s", tc.wantVersion, v.String())
			}
		})
	}
}
