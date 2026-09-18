package idpsession

import (
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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
	if i.Claims != nil {
		claims := i.Claims.AsMap()
		// same as pkg/identity/manager/data.go#104
		// To preserve existing behavior: filter out claims not related to user info.
		delete(claims, "iss")
		delete(claims, "sub")
		delete(claims, "exp")
		delete(claims, "iat")
		s.AddClaims(identity.FlattenedClaims(mapsutil.Flatten(claims)))
	}
	return s
}

func (i *idpSessionApplier) ApplyToUser(u *user.User) {
	if u == nil {
		return
	}
	if i == nil || i.Claims == nil {
		return
	}
	u.AddClaims(identity.Claims(i.Claims.AsMap()).Flatten())
}
