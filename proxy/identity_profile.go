package proxy

import (
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/identity/manager"
	"github.com/pomerium/pomerium/internal/sessions"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func newSessionStateFromProfile(p *identitypb.Profile) *sessions.State {
	claims := p.GetClaims().AsMap()

	ss := sessions.NewState(p.GetProviderId())

	// set the subject
	if v, ok := claims["sub"]; ok {
		ss.Subject = fmt.Sprint(v)
	} else if v, ok := claims["user"]; ok {
		ss.Subject = fmt.Sprint(v)
	}

	// set the oid
	if v, ok := claims["oid"]; ok {
		ss.OID = fmt.Sprint(v)
	}

	return ss
}

func populateSessionFromProfile(s *session.Session, p *identitypb.Profile, ss *sessions.State, cookieExpire time.Duration) {
	claims := p.GetClaims().AsMap()
	oauthToken := new(oauth2.Token)
	_ = json.Unmarshal(p.GetOauthToken(), oauthToken)

	s.UserId = ss.UserID()
	s.IssuedAt = timestamppb.Now()
	s.AccessedAt = timestamppb.Now()
	s.ExpiresAt = timestamppb.New(time.Now().Add(cookieExpire))
	s.IdToken = &session.IDToken{
		Issuer:    ss.Issuer,
		Subject:   ss.Subject,
		ExpiresAt: timestamppb.New(time.Now().Add(cookieExpire)),
		IssuedAt:  timestamppb.Now(),
		Raw:       string(p.GetIdToken()),
	}
	s.OauthToken = manager.ToOAuthToken(oauthToken)
	if s.Claims == nil {
		s.Claims = make(map[string]*structpb.ListValue)
	}
	for k, vs := range identity.Claims(claims).Flatten().ToPB() {
		s.Claims[k] = vs
	}
}

func populateUserFromProfile(u *user.User, p *identitypb.Profile, _ *sessions.State) {
	claims := p.GetClaims().AsMap()
	if v, ok := claims["name"]; ok {
		u.Name = fmt.Sprint(v)
	}
	if v, ok := claims["email"]; ok {
		u.Email = fmt.Sprint(v)
	}
	if u.Claims == nil {
		u.Claims = make(map[string]*structpb.ListValue)
	}
	for k, vs := range identity.Claims(claims).Flatten().ToPB() {
		u.Claims[k] = vs
	}
}
