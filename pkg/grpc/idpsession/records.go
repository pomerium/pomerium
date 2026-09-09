package idpsession

import (
	"context"
	"time"

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

func RevokeBinding(ctx context.Context, client databroker.DataBrokerServiceClient, bindingID string) error {
	rec, err := client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/idpsession.Binding",
		Id:   bindingID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return err
	}
	binding := &Binding{}
	if err := rec.Record.GetData().UnmarshalTo(binding); err != nil {
		return err
	}

	if binding.GetRevokedAt() != nil {
		return nil
	}
	nB := proto.CloneOf(binding)
	nB.State = BindingState_BindingState_REVOKED
	nB.RevokedAt = timestamppb.Now()
	_, putErr := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(nB),
		},
	})
	return putErr
}

func RevokeIDPSession(ctx context.Context, client databroker.DataBrokerServiceClient, id string, reason string) error {
	rec, err := client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/idpsession.IDPSession",
		Id:   id,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return err
	}
	idpSess := &IDPSession{}
	if err := rec.Record.GetData().UnmarshalTo(idpSess); err != nil {
		return err
	}

	if idpSess.GetState().GetInvalidatedAt() != nil {
		return nil
	}
	iS := proto.CloneOf(idpSess)
	iS.State = &SessionState{
		State:         UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
		InvalidatedAt: timestamppb.Now(),
		Details:       reason,
	}
	_, putErr := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			databroker.NewRecord(iS),
		},
	})
	return putErr
}
