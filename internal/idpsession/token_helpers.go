package idpsession

import (
	"context"
	"errors"

	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FromOAuthToken converts an idpsession token to oauth2.Token.
func FromOAuthToken(idpSess *idpsession.IDPSession) *oauth2.Token {
	token := idpSess.GetOauthToken()
	return &oauth2.Token{
		AccessToken:  token.GetAccessToken(),
		TokenType:    token.GetTokenType(),
		RefreshToken: token.GetRefreshToken(),
		Expiry:       token.GetExpiresAt().AsTime(),
	}
}

// UpdateOAuthToken applies an oauth2.Token to an idpsession.
func UpdateOAuthToken(token *oauth2.Token, idpSess *idpsession.IDPSession) {
	if idpSess.OauthToken == nil {
		idpSess.OauthToken = new(idpsession.OAuthToken)
	}

	idpSess.OauthToken.AccessToken = token.AccessToken
	idpSess.OauthToken.TokenType = token.TokenType
	idpSess.OauthToken.ExpiresAt = timestamppb.New(token.Expiry)
	if token.RefreshToken != "" {
		idpSess.OauthToken.RefreshToken = token.RefreshToken
	}
}

func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var hasTemporary interface{ Temporary() bool }
	if errors.As(err, &hasTemporary) && hasTemporary.Temporary() {
		return true
	}
	return false
}
