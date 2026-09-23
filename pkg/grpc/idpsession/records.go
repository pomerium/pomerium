package idpsession

import (
	"context"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
func NewFromSession(s *session.Session, claims *structpb.Struct) *IDPSession {
	return &IDPSession{
		Id:         s.GetUserId(),
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
		State: &SessionState{
			State: UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID,
		},
		Claims: claims,
		IdpId:  s.GetIdpId(),
		UserId: s.GetUserId(),
	}
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
func NewBinding(idpSessionID string, protocol BindingProtocol, dependent BindableRecord, details map[string]string) *Binding {
	return &Binding{
		Id:           dependent.GetId(),
		TypeUrl:      protoutil.GetTypeURL(dependent),
		IdpSessionId: idpSessionID,
		Protocol:     protocol,
		Details:      details,
		InitiatedAt:  timestamppb.Now(),
	}
}

// NewBoundRecords returns a dependent record and its matching binding.
func NewBoundRecords(idpSessionID string, protocol BindingProtocol, details map[string]string, dependent BindableRecord) []*databroker.Record {
	binding := NewBinding(idpSessionID, protocol, dependent, details)
	return []*databroker.Record{
		databroker.NewRecord(dependent),
		databroker.NewRecord(binding),
	}
}

// GetIDPSession reads a centralized upstream IdP session record, keyed by user
// id. The gRPC error is returned unwrapped so callers can test codes.NotFound.
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
// dependent credential may still be issued from. A session that has been
// invalidated (the user signed out or the provider revoked them) is reported
// the same way as a missing one, as a codes.NotFound error, so callers keep a
// single "no usable session" branch. Only the state is checked: an expired
// copy of the upstream access token does not make the session unusable, since
// the identity manager refreshes it out of band.
func GetValidIDPSession(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*IDPSession, error) {
	idpSess, err := GetIDPSession(ctx, client, id)
	if err != nil {
		return nil, err
	}
	if st := idpSess.GetState(); st.GetState() == UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
		return nil, status.Errorf(codes.NotFound, "idpsession %q is no longer valid: %s", id, st.GetDetails())
	}
	return idpSess, nil
}

// GetActiveBinding reads a Binding that still ties its dependent to the IdP
// session. A revoked binding is reported the same way as a missing one, as a
// codes.NotFound error: either way the dependent may no longer act.
func GetActiveBinding(ctx context.Context, client databroker.DataBrokerServiceClient, id string) (*Binding, error) {
	binding, err := GetBinding(ctx, client, id)
	if err != nil {
		return nil, err
	}
	if binding.GetState() == BindingState_BindingState_REVOKED {
		return nil, status.Errorf(codes.NotFound, "binding %q is revoked", id)
	}
	return binding, nil
}

func RevokeBinding(ctx context.Context, client databroker.DataBrokerServiceClient, bindingID string) error {
	binding, err := GetBinding(ctx, client, bindingID)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return err
	}

	nB := proto.CloneOf(binding)
	nB.State = BindingState_BindingState_REVOKED
	_, putErr := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(nB),
		},
	})
	return putErr
}

func RevokeIDPSession(ctx context.Context, client databroker.DataBrokerServiceClient, id string, reason string) (*oauth2.Token, error) {
	idpSess, err := GetIDPSession(ctx, client, id)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}

	iS := proto.CloneOf(idpSess)
	iS.State = &SessionState{
		State:   UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
		Details: reason,
	}
	_, putErr := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(iS),
		},
	})

	return FromOAuthToken(idpSess), putErr
}

func (b *Binding) Revoke() *Binding {
	if b.GetState() == BindingState_BindingState_REVOKED {
		return b
	}
	b = proto.CloneOf(b)
	b.State = BindingState_BindingState_REVOKED
	return b
}
