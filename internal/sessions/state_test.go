package sessions

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
			if gotEmail := s.RequestEmail(); gotEmail != tt.wantResponseEmail {
				t.Errorf("State.RequestEmail() = %v, want %v", gotEmail, tt.wantResponseEmail)
			}
			if gotGroups := s.RequestGroups(); gotGroups != tt.wantResponseGroups {
				t.Errorf("State.v() = %v, want %v", gotGroups, tt.wantResponseGroups)
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
		{"bad access token expiry", []string{"a", "b", "c"}, jwt.NewNumericDate(time.Now().Add(time.Hour)), jwt.NewNumericDate(time.Now().Add(-time.Hour)), jwt.NewNumericDate(time.Now().Add(-time.Hour)), &oauth2.Token{Expiry: time.Now().Add(-time.Hour)}, "a", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &State{
				Audience:    tt.Audience,
				Expiry:      tt.Expiry,
				NotBefore:   tt.NotBefore,
				IssuedAt:    tt.IssuedAt,
				AccessToken: tt.AccessToken,
			}
			if exp := s.IsExpired(); exp != tt.wantErr {
				t.Errorf("State.IsExpired() error = %v, wantErr %v", exp, tt.wantErr)
			}
		})
	}
}

func TestState_RouteSession(t *testing.T) {
	now := time.Now()
	timeNow = func() time.Time {
		return now
	}
	tests := []struct {
		name        string
		Issuer      string
		Audience    jwt.Audience
		Expiry      *jwt.NumericDate
		AccessToken *oauth2.Token

		issuer string

		audience []string

		want *State
	}{
		{"good", "authenticate.x.y.z", []string{"http.x.y.z"}, jwt.NewNumericDate(timeNow()), nil, "authenticate.a.b.c", []string{"http.a.b.c"}, &State{Issuer: "authenticate.a.b.c", Audience: []string{"http.a.b.c"}, NotBefore: jwt.NewNumericDate(timeNow()), IssuedAt: jwt.NewNumericDate(timeNow()), Expiry: jwt.NewNumericDate(timeNow())}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := State{
				Issuer:      tt.Issuer,
				Audience:    tt.Audience,
				Expiry:      tt.Expiry,
				AccessToken: tt.AccessToken,
			}
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(State{}),
			}
			got := s.NewSession(tt.issuer, tt.audience)
			got = got.RouteSession()
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("State.RouteSession() = %s", diff)
			}

		})
	}
}

func TestState_accessTokenHash(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		state State
		want  string
	}{
		{"empty access token", State{}, "34c96acdcadb1bbb"},
		{"no change to access token", State{Subject: "test"}, "34c96acdcadb1bbb"},
		{"empty oauth2 token", State{AccessToken: &oauth2.Token{}}, "bbd82197d215198f"},
		{"refresh token a", State{AccessToken: &oauth2.Token{RefreshToken: "a"}}, "76316ac79b301bd6"},
		{"refresh token b", State{AccessToken: &oauth2.Token{RefreshToken: "b"}}, "fab7cb29e50161f1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &tt.state
			if got := s.accessTokenHash(); got != tt.want {
				t.Errorf("State.accessTokenHash() = %v, want %v", got, tt.want)
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
		{"good", &State{}, State{}, false},
		{"with user", &State{User: "user"}, State{User: "user"}, false},
		{"without", &State{Subject: "user"}, State{User: "user", Subject: "user"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatal(err)
			}

			s := &State{}
			if err := s.UnmarshalJSON(data); (err != nil) != tt.wantErr {
				t.Errorf("State.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			got := *s
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(State{}),
			}
			if diff := cmp.Diff(got, tt.want, cmpOpts...); diff != "" {
				t.Errorf("State.UnmarshalJSON() error = %v", diff)
			}
		})
	}
}
