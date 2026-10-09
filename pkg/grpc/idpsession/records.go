package idpsession

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// BindableRecord is a protobuf Data Broker record with an ID.
type BindableRecord interface {
	proto.Message
	GetId() string
}

// NewFromSession creates an IDPSession from a browser-iniated session.
func NewFromSession(
	id string,
	s *session.Session,
	claims *structpb.Struct,
	sid string,
) *IDPSession {
	idpSess := &IDPSession{
		Id:         id,
		RawIdToken: s.GetIdToken().GetRaw(),
		IdToken: &IDToken{
			Issuer:    s.GetIdToken().GetIssuer(),
			Subject:   s.GetIdToken().GetSubject(),
			ExpiresAt: s.GetIdToken().GetExpiresAt(),
			IssuedAt:  s.GetIdToken().GetIssuedAt(),
			Raw:       s.GetIdToken().GetRaw(),
		},
		OauthToken: &OAuthToken{
			AccessToken:  s.GetOauthToken().GetAccessToken(),
			TokenType:    s.GetOauthToken().GetTokenType(),
			ExpiresAt:    s.GetOauthToken().GetExpiresAt(),
			RefreshToken: s.GetOauthToken().GetRefreshToken(),
		},
		Claims:      claims,
		IdpId:       s.GetIdpId(),
		UserId:      s.GetUserId(),
		InitiatedAt: timestamppb.Now(),
	}
	if sid != "" {
		idpSess.Sid = new(sid)
	}
	return idpSess
}

// IssueSession creates a session.Session from an IDPSession. It is the
// inverse of NewFromSession, so session fields not carried by an IDPSession
// (device credentials, audience) are left unset.
func IssueSession(newSessionID string, idpSess *IDPSession, iat time.Time, expiry time.Duration) *session.Session {
	if idpSess == nil {
		return nil
	}

	s := &session.Session{
		Id:     newSessionID,
		UserId: idpSess.GetUserId(),
		IdpId:  idpSess.GetIdpId(),
	}
	if t := idpSess.GetIdToken(); t != nil {
		s.IdToken = &session.IDToken{
			Issuer:    t.GetIssuer(),
			Subject:   t.GetSubject(),
			ExpiresAt: t.GetExpiresAt(),
			IssuedAt:  t.GetIssuedAt(),
			Raw:       t.GetRaw(),
		}
	}
	if t := idpSess.GetOauthToken(); t != nil {
		s.OauthToken = &session.OAuthToken{
			AccessToken:  t.GetAccessToken(),
			TokenType:    t.GetTokenType(),
			ExpiresAt:    t.GetExpiresAt(),
			RefreshToken: t.GetRefreshToken(),
		}
	}
	if claims := idpSess.GetClaims(); claims != nil {
		s.AddClaims(identity.Claims(claims.AsMap()).Flatten())
	}
	s.IssuedAt = timestamppb.New(iat)
	s.AccessedAt = timestamppb.New(iat)
	s.ExpiresAt = timestamppb.New(iat.Add(expiry))
	return s
}

// NewBinding binds a dependent record to an upstream IdP session.
func NewBinding(idpSessionID string, userID string, protocol BindingProtocol, dependent BindableRecord, details map[string]string) *Binding {
	return &Binding{
		Id:           dependent.GetId(),
		TypeUrl:      protoutil.GetTypeURL(dependent),
		IdpSessionId: idpSessionID,
		UserId:       userID,
		Protocol:     protocol,
		Details:      details,
		InitiatedAt:  timestamppb.Now(),
	}
}

// NewBoundRecords returns a dependent record and its matching binding.
func NewBoundRecords(idpSessionID string, userID string, protocol BindingProtocol, details map[string]string, dependent BindableRecord) []*databroker.Record {
	binding := NewBinding(idpSessionID, userID, protocol, dependent, details)
	return []*databroker.Record{
		databroker.NewRecord(dependent),
		databroker.NewRecord(binding),
	}
}

// GetIDPSession reads a centralized upstream IdP session record by its id. The
// gRPC error is returned unwrapped so callers can test codes.NotFound.
func GetIDPSession(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*IDPSession, error) {
	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(new(IDPSession)),
		Id:   id,
	})
	if err != nil {
		return nil, err
	}
	idpSess := new(IDPSession)
	if err := res.GetRecord().GetData().UnmarshalTo(idpSess); err != nil {
		return nil, err
	}
	return idpSess, nil
}

// GetBinding reads the Binding whose id is its dependent client record's id.
// The gRPC error is returned unwrapped so callers can test codes.NotFound.
func GetBinding(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*Binding, error) {
	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(new(Binding)),
		Id:   id,
	})
	if err != nil {
		return nil, err
	}
	binding := new(Binding)
	if err := res.GetRecord().GetData().UnmarshalTo(binding); err != nil {
		return nil, err
	}
	return binding, nil
}

// GetValidIDPSession reads a centralized upstream IdP session that a new
// dependent credential may still be issued from. Invalidation (the user
// signed out, the provider revoked them, or the session sat idle with no
// bindings) deletes the record, so an unusable session is reported the same
// way as a missing one, as a codes.NotFound error, and callers keep a single
// "no usable session" branch. An expired copy of the upstream access token
// does not make the session unusable, since the identity manager refreshes it
// out of band.
func GetValidIDPSession(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*IDPSession, error) {
	idpSess, err := GetIDPSession(ctx, client, id)
	if err != nil {
		return nil, err
	}
	return idpSess, nil
}

// GetActiveBinding reads a Binding that still ties its dependent to the IdP
// session. Revocation deletes the record, so a revoked binding is reported the
// same way as a missing one, as a codes.NotFound error: either way the
// dependent may no longer act.
func GetActiveBinding(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*Binding, error) {
	binding, err := GetBinding(ctx, client, id)
	if err != nil {
		return nil, err
	}
	return binding, nil
}
