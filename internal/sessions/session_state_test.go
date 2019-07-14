package sessions

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/pomerium/internal/cryptutil"
)

func TestSessionStateSerialization(t *testing.T) {
	secret := cryptutil.GenerateKey()
	c, err := cryptutil.NewCipher(secret)
	if err != nil {
		t.Fatalf("expected to be able to create cipher: %v", err)
	}

	want := &SessionState{
		AccessToken:     "token1234",
		RefreshToken:    "refresh4321",
		RefreshDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(),
		Email:           "user@domain.com",
		User:            "user",
	}

	ciphertext, err := MarshalSession(want, c)
	if err != nil {
		t.Fatalf("expected to be encode session: %v", err)
	}

	got, err := UnmarshalSession(ciphertext, c)
	if err != nil {
		t.Fatalf("expected to be decode session: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Logf("want: %#v", want)
		t.Logf(" got: %#v", got)
		t.Errorf("encoding and decoding session resulted in unexpected output")
	}
}

func TestSessionStateExpirations(t *testing.T) {
	session := &SessionState{
		AccessToken:     "token1234",
		RefreshToken:    "refresh4321",
		RefreshDeadline: time.Now().Add(-1 * time.Hour),
		Email:           "user@domain.com",
		User:            "user",
	}
	if !session.RefreshPeriodExpired() {
		t.Errorf("expected lifetime period to be expired")
	}

}

func TestExtendDeadline(t *testing.T) {
	// tons of wiggle room here
	now := time.Now().Truncate(time.Second)
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Time
	}{
		{"Add a few ms", time.Millisecond * 10, now.Truncate(time.Second)},
		{"Add a few microsecs", time.Microsecond * 10, now.Truncate(time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtendDeadline(tt.ttl); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtendDeadline() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionState_IssuedAt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		IDToken string
		want    time.Time
		wantErr bool
	}{
		{"simple parse", "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3YTA4MjgzOWYyZTcxYTliZjZjNTk2OTk2Yjk0NzM5Nzg1YWZkYzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4NTE4NzcwODIwNTktYmZna3BqMDlub29nN2FzM2dwYzN0N3I2bjlzamJnczYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTE0MzI2NTU5NzcyNzMxNTAzMDgiLCJoZCI6InBvbWVyaXVtLmlvIiwiZW1haWwiOiJiZGRAcG9tZXJpdW0uaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IlkzYm1qV3R4US16OW1fM1RLb0dtRWciLCJuYW1lIjoiQm9iYnkgRGVTaW1vbmUiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1PX1BzRTlILTgzRS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BQ0hpM3JjQ0U0SFRLVDBhQk1pUFVfOEZfVXFOQ3F6RTBRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJCb2JieSIsImZhbWlseV9uYW1lIjoiRGVTaW1vbmUiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTU1ODY3MjY4NywiZXhwIjoxNTU4Njc2Mjg3fQ.a4g8W94E7iVJhiIUmsNMwJssfx3Evi8sXeiXgXMC7kHNvftQ2CFU_LJ-dqZ5Jf61OXcrp26r7lUcTNENXuen9tyUWAiHvxk6OHTxZusdywTCY5xowpSZBO9PDWYrmmdvfhRbaKO6QVAUMkbKr1Tr8xqfoaYVXNZhERXhcVReDznI0ccbwCGrNx5oeqiL4eRdZY9eqFXi4Yfee0mkef9oyVPc2HvnpwcpM0eckYa_l_ZQChGjXVGBFIus_Ao33GbWDuc9gs-_Vp2ev4KUT2qWb7AXMCGDLx0tWI9umm7mCBi_7xnaanGKUYcVwcSrv45arllAAwzuNxO0BVw3oRWa5Q", time.Unix(1558672687, 0), false},
		{"bad jwt", "x.x.x-x-x", time.Time{}, true},
		{"malformed jwt", "x", time.Time{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SessionState{IDToken: tt.IDToken}
			got, err := s.IssuedAt()
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionState.IssuedAt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SessionState.IssuedAt() = %v, want %v", got.Format(time.RFC3339), tt.want.Format(time.RFC3339))
			}
		})
	}
}

func TestSessionState_Impersonating(t *testing.T) {
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
			s := &SessionState{
				Email:             tt.Email,
				Groups:            tt.Groups,
				ImpersonateEmail:  tt.ImpersonateEmail,
				ImpersonateGroups: tt.ImpersonateGroups,
			}
			if got := s.Impersonating(); got != tt.want {
				t.Errorf("SessionState.Impersonating() = %v, want %v", got, tt.want)
			}
			if gotEmail := s.RequestEmail(); gotEmail != tt.wantResponseEmail {
				t.Errorf("SessionState.RequestEmail() = %v, want %v", gotEmail, tt.wantResponseEmail)
			}
			if gotGroups := s.RequestGroups(); gotGroups != tt.wantResponseGroups {
				t.Errorf("SessionState.v() = %v, want %v", gotGroups, tt.wantResponseGroups)
			}
		})
	}
}

func TestMarshalSession(t *testing.T) {
	secret := cryptutil.GenerateKey()
	c, err := cryptutil.NewCipher(secret)
	if err != nil {
		t.Fatalf("expected to be able to create cipher: %v", err)
	}
	hugeString := make([]byte, 4097)
	if _, err := rand.Read(hugeString); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		s       *SessionState
		wantErr bool
	}{
		{"simple", &SessionState{}, false},
		{"too big", &SessionState{AccessToken: fmt.Sprintf("%x", hugeString)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, err := MarshalSession(tt.s, c)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				out, err := UnmarshalSession(in, c)
				if err != nil {
					t.Fatalf("expected to be decode session: %v", err)
				}
				if diff := cmp.Diff(tt.s, out); diff != "" {
					t.Errorf("MarshalSession() = %s", diff)
				}
			}
		})
	}
}
