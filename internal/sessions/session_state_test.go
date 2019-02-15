package sessions

import (
	"reflect"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

func TestSessionStateSerialization(t *testing.T) {
	secret := cryptutil.GenerateKey()
	c, err := cryptutil.NewCipher([]byte(secret))
	if err != nil {
		t.Fatalf("expected to be able to create cipher: %v", err)
	}

	want := &SessionState{
		AccessToken:      "token1234",
		RefreshToken:     "refresh4321",
		LifetimeDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(),
		RefreshDeadline:  time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(),
		Email:            "user@domain.com",
		User:             "user",
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
		AccessToken:      "token1234",
		RefreshToken:     "refresh4321",
		LifetimeDeadline: time.Now().Add(-1 * time.Hour),
		RefreshDeadline:  time.Now().Add(-1 * time.Hour),
		Email:            "user@domain.com",
		User:             "user",
	}

	if !session.LifetimePeriodExpired() {
		t.Errorf("expected lifetime period to be expired")
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
