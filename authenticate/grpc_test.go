package authenticate

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/identity"

	"github.com/golang/protobuf/ptypes"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/sessions"
	pb "github.com/pomerium/pomerium/proto/authenticate"
)

var fixedDate = time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)

func TestAuthenticate_Validate(t *testing.T) {
	tests := []struct {
		name    string
		idToken string
		mp      *identity.MockProvider
		want    bool
		wantErr bool
	}{
		{"good", "example", &identity.MockProvider{}, false, false},
		{"error", "error", &identity.MockProvider{ValidateError: errors.New("err")}, false, true},
		{"not error", "not error", &identity.MockProvider{ValidateError: nil}, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Authenticate{provider: tt.mp}
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
		name            string
		mock            *identity.MockProvider
		originalSession *pb.Session
		want            *pb.Session
		wantErr         bool
	}{
		{"good",
			&identity.MockProvider{
				RefreshResponse: &sessions.SessionState{
					AccessToken:      "updated",
					LifetimeDeadline: fixedDate,
					RefreshDeadline:  fixedDate,
				}},
			&pb.Session{
				AccessToken:      "original",
				LifetimeDeadline: fixedProtoTime,
				RefreshDeadline:  fixedProtoTime,
			},
			&pb.Session{
				AccessToken:      "updated",
				LifetimeDeadline: fixedProtoTime,
				RefreshDeadline:  fixedProtoTime,
			},
			false},
		{"test error", &identity.MockProvider{RefreshError: errors.New("hi")}, &pb.Session{RefreshToken: "refresh token", RefreshDeadline: fixedProtoTime, LifetimeDeadline: fixedProtoTime}, nil, true},
		{"test catch nil", nil, nil, nil, true},

		// {"test error", "error", nil, true},
		// {"test bad time", "bad time", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Authenticate{provider: tt.mock}

			got, err := p.Refresh(context.Background(), tt.originalSession)
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
	vtProto, err := ptypes.TimestampProto(rt)
	if err != nil {
		t.Fatal("failed to parse timestamp")
	}

	want := &sessions.SessionState{
		AccessToken:      "token1234",
		RefreshToken:     "refresh4321",
		LifetimeDeadline: lt,
		RefreshDeadline:  rt,

		Email: "user@domain.com",
		User:  "user",
	}

	goodReply := &pb.Session{
		AccessToken:      "token1234",
		RefreshToken:     "refresh4321",
		LifetimeDeadline: vtProto,
		RefreshDeadline:  vtProto,
		Email:            "user@domain.com",
		User:             "user"}
	ciphertext, err := sessions.MarshalSession(want, c)
	if err != nil {
		t.Fatalf("expected to be encode session: %v", err)
	}

	tests := []struct {
		name    string
		cipher  cryptutil.Cipher
		code    string
		want    *pb.Session
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
				t.Errorf("Authenticate.Authenticate() = got: \n%vwant:\n%v", got, tt.want)
			}
		})
	}
}
