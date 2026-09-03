package idpsession

import (
	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	identitymanager "github.com/pomerium/pomerium/pkg/identity/manager"
	"google.golang.org/protobuf/proto"
)

func bindingCmp(r1, r2 *databroker.Record) bool {
	// TODO : maybe needs a reconciler that uses patch from recordSetsBudles
	return proto.Equal(r1.GetData(), r2.GetData())
}

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
		claims, err := i.Claims.MarshalJSON()
		if err != nil {
			panic(err)
		}
		if err := identitymanager.NewSessionUnmarshaler(s).UnmarshalJSON(claims); err != nil {
			panic(err)
		}
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
	u.Claims = identity.Claims(i.Claims.AsMap()).Flatten().ToPB()
}

func (i *idpSessionApplier) ApplyToMCP(token *oauth21.MCPRefreshToken) *oauth21.MCPRefreshToken {
	if token == nil {
		return nil
	}
	if i != nil {
		token.UpstreamRefreshToken = i.OauthToken.GetRefreshToken()
	}
	return token
}
