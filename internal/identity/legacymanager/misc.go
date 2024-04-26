package legacymanager

import (
	"strings"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func toSessionSchedulerKey(userID, sessionID string) string {
	return userID + "\037" + sessionID
}

func fromSessionSchedulerKey(key string) (userID, sessionID string) {
	idx := strings.Index(key, "\037")
	if idx >= 0 {
		userID = key[:idx]
		sessionID = key[idx+1:]
	} else {
		userID = key
	}
	return userID, sessionID
}

// FromOAuthToken converts a session oauth token to oauth2.Token.
func FromOAuthToken(token *session.OAuthToken) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  token.GetAccessToken(),
		TokenType:    token.GetTokenType(),
		RefreshToken: token.GetRefreshToken(),
		Expiry:       token.GetExpiresAt().AsTime(),
	}
}

// ToOAuthToken converts an oauth2.Token to a session oauth token.
func ToOAuthToken(token *oauth2.Token) *session.OAuthToken {
	expiry := timestamppb.New(token.Expiry)
	return &session.OAuthToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    expiry,
	}
}
