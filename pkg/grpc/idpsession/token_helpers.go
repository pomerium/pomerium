package idpsession

import (
	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/oauth2"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

// ParseIDToken converts a raw ID token into an IDToken proto message.
// Does not perform any verification of the ID token.
func ParseIDToken(idToken string) (*IDToken, error) {
	if idToken == "" {
		return nil, nil
	}

	token, err := jwt.ParseSigned(idToken)
	if err != nil {
		return nil, err
	}
	var claims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}
	return &IDToken{
		Raw:       idToken,
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		ExpiresAt: timestamppb.New(claims.Expiry.Time()),
		IssuedAt:  timestamppb.New(claims.IssuedAt.Time()),
	}, nil
}

// FromOAuthToken converts an idpsession token to oauth2.Token.
func FromOAuthToken(idpSess *IDPSession) *oauth2.Token {
	token := idpSess.GetOauthToken()
	return &oauth2.Token{
		AccessToken:  token.GetAccessToken(),
		TokenType:    token.GetTokenType(),
		RefreshToken: token.GetRefreshToken(),
		Expiry:       token.GetExpiresAt().AsTime(),
	}
}

// UpdateOAuthToken applies an oauth2.Token to an idpsession.
func UpdateOAuthToken(token *oauth2.Token, idpSess *IDPSession) {
	if idpSess.OauthToken == nil {
		idpSess.OauthToken = new(OAuthToken)
	}

	idpSess.OauthToken.AccessToken = token.AccessToken
	idpSess.OauthToken.TokenType = token.TokenType
	idpSess.OauthToken.ExpiresAt = timestamppb.New(token.Expiry)
	if token.RefreshToken != "" {
		idpSess.OauthToken.RefreshToken = token.RefreshToken
	}
}

func SessionOauthTokenConversion(tok *session.OAuthToken) *OAuthToken {
	return &OAuthToken{
		AccessToken:  tok.GetAccessToken(),
		TokenType:    tok.GetTokenType(),
		ExpiresAt:    tok.GetExpiresAt(),
		RefreshToken: tok.GetRefreshToken(),
	}
}

func (x *OAuthToken) AsOAuth2Token() *oauth2.Token {
	if x == nil {
		return nil
	}
	return &oauth2.Token{
		AccessToken:  x.GetAccessToken(),
		TokenType:    x.GetTokenType(),
		RefreshToken: x.GetRefreshToken(),
		Expiry:       x.GetExpiresAt().AsTime(),
	}
}

func SIDClaim(claims identity.Claims) string {
	if claims == nil {
		return ""
	}
	sid, ok := claims["sid"]
	if !ok {
		return ""
	}
	ssid, ok := sid.(string)
	if !ok {
		return ""
	}
	return ssid
}
