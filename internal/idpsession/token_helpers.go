package idpsession

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// FromOAuthToken converts an idpsession token to oauth2.Token.
func FromOAuthToken(idpSess *api.IDPSession) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  idpSess.GetAccessToken().GetToken(),
		TokenType:    idpSess.GetAccessToken().GetType(),
		RefreshToken: idpSess.GetRefreshToken().GetToken(),
		Expiry:       idpSess.GetRefreshToken().ExpiresAt.AsTime(),
	}
}

// UpdateOAuthToken applies an oauth2.Token to an idpsession.
func UpdateOAuthToken(token *oauth2.Token, idpsession *api.IDPSession) {
	expiry := timestamppb.New(token.Expiry)

	if idpsession.AccessToken == nil {
		idpsession.AccessToken = &api.AccessToken{}
	}
	idpsession.AccessToken.Token = token.AccessToken
	idpsession.AccessToken.Type = token.TokenType

	if idpsession.RefreshToken == nil {
		idpsession.RefreshToken = &api.RefreshToken{}
	}
	if token.RefreshToken != "" {
		idpsession.RefreshToken.Token = token.RefreshToken
	}
	idpsession.RefreshToken.ExpiresAt = expiry
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
