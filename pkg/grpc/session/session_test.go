package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSession_Validate(t *testing.T) {
	t.Parallel()

	t0 := timestamppb.New(time.Now().Add(-time.Second))
	for _, tc := range []struct {
		name    string
		session *Session
		expect  error
	}{
		{"valid", &Session{}, nil},
		{"expired", &Session{ExpiresAt: t0}, ErrSessionExpired},
		{"expired id token", &Session{IdToken: &IDToken{ExpiresAt: t0}}, ErrSessionExpired},
		{"expired oauth token", &Session{OauthToken: &OAuthToken{ExpiresAt: t0}}, ErrSessionExpired},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.ErrorIs(t, tc.session.Validate(), tc.expect)
		})
	}
}
