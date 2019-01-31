package authenticate

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authenticate"
	"golang.org/x/oauth2"
)

var fixedDate = time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)

// TestProvider is a mock provider
type testProvider struct{}

func (tp *testProvider) Authenticate(s string) (*sessions.SessionState, error) {
	return &sessions.SessionState{}, nil
}

func (tp *testProvider) Revoke(s string) error        { return nil }
func (tp *testProvider) GetSignInURL(s string) string { return "/signin" }
func (tp *testProvider) Refresh(s string) (*oauth2.Token, error) {
	if s == "error" {
		return nil, errors.New("failed refresh")
	}
	if s == "bad time" {
		return &oauth2.Token{AccessToken: "updated", Expiry: time.Time{}}, nil
	}
	return &oauth2.Token{AccessToken: "updated", Expiry: fixedDate}, nil
}
func (tp *testProvider) Validate(token string) (bool, error) {
	if token == "good" {
		return true, nil
	} else if token == "error" {
		return false, errors.New("error validating id token")
	}
	return false, nil
}

func TestAuthenticate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		idToken string
		want    bool
		wantErr bool
	}{
		{"good", "example", false, false},
		{"error", "error", false, true},
		{"not error", "not error", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &testProvider{}
			p := &Authenticate{provider: tp}
			got, err := p.Validate(context.Background(), &pb.ValidateRequest{IdToken: tt.idToken})
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.IsValid, tt.want) {
				t.Errorf("Authenticate.Validate() = %v, want %v", got.IsValid, tt.want)
			}
		})
	}
}

func TestAuthenticate_Refresh(t *testing.T) {
	fixedProtoTime, err := ptypes.TimestampProto(fixedDate)
	if err != nil {
		t.Fatal("failed to parse timestamp")
	}

	tests := []struct {
		name         string
		refreshToken string
		want         *pb.RefreshReply
		wantErr      bool
	}{
		{"good", "refresh-token", &pb.RefreshReply{AccessToken: "updated", Expiry: fixedProtoTime}, false},
		{"test error", "error", nil, true},
		// {"test bad time", "bad time", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &testProvider{}
			p := &Authenticate{provider: tp}

			got, err := p.Refresh(context.Background(), &pb.RefreshRequest{RefreshToken: tt.refreshToken})
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate.Refresh() error = %v, wantErr %v", err, tt.wantErr)

			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authenticate.Refresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticate_Authenticate(t *testing.T) {
	secret := cryptutil.GenerateKey()
	c, err := cryptutil.NewCipher([]byte(secret))
	if err != nil {
		t.Fatalf("expected to be able to create cipher: %v", err)
	}
	newSecret := cryptutil.GenerateKey()
	c2, err := cryptutil.NewCipher([]byte(newSecret))
	if err != nil {
		t.Fatalf("expected to be able to create cipher: %v", err)
	}
	lt := time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC()
	rt := time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC()
	vt := time.Now().Add(1 * time.Minute).Truncate(time.Second).UTC()
	vtProto, err := ptypes.TimestampProto(rt)
	if err != nil {
		t.Fatal("failed to parse timestamp")
	}

	want := &sessions.SessionState{
		AccessToken:      "token1234",
		RefreshToken:     "refresh4321",
		LifetimeDeadline: lt,
		RefreshDeadline:  rt,
		ValidDeadline:    vt,
		Email:            "user@domain.com",
		User:             "user",
	}

	goodReply := &pb.AuthenticateReply{
		AccessToken:  "token1234",
		RefreshToken: "refresh4321",
		Expiry:       vtProto,
		Email:        "user@domain.com",
		User:         "user"}
	ciphertext, err := sessions.MarshalSession(want, c)
	if err != nil {
		t.Fatalf("expected to be encode session: %v", err)
	}

	tests := []struct {
		name    string
		cipher  cryptutil.Cipher
		code    string
		want    *pb.AuthenticateReply
		wantErr bool
	}{
		{"good", c, ciphertext, goodReply, false},
		{"bad cipher", c2, ciphertext, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Authenticate{cipher: tt.cipher}
			got, err := p.Authenticate(context.Background(), &pb.AuthenticateRequest{Code: tt.code})
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Authenticate.Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}
