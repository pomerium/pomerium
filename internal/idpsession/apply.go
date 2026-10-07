package idpsession

import (
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/mapsutil"
)

type idpSessionApplier struct {
	*idpsession.IDPSession
}

func (i *idpSessionApplier) ApplyToSession(s *session.Session) *session.Session {
	if s == nil {
		return nil
	}
	if i == nil {
		return s
	}
	if i.IdToken != nil {
		s.IdToken = &session.IDToken{
			Issuer:    i.IdToken.Issuer,
			Subject:   i.IdToken.Subject,
			ExpiresAt: i.IdToken.ExpiresAt,
			IssuedAt:  i.IdToken.IssuedAt,
			Raw:       i.IdToken.Raw,
		}
	}
	if i.OauthToken != nil {
		s.OauthToken = &session.OAuthToken{
			AccessToken:  i.OauthToken.AccessToken,
			TokenType:    i.OauthToken.TokenType,
			ExpiresAt:    i.OauthToken.ExpiresAt,
			RefreshToken: i.OauthToken.RefreshToken,
		}
	}
	claims := i.Claims
	if claims == nil {
		return s
	}
	m := claims.AsMap()
	s.AddClaims(identity.FlattenedClaims(mapsutil.Flatten(m)))
	return s
}

func patchFieldMask(typeURL string) []string {
	switch typeURL {
	case sessionTypeURL:
		return []string{"id_token", "oauth_token", "claims"}
	default:
		return nil
	}
}
