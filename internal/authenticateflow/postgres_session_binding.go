package authenticateflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/postgresidentity"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var (
	// ErrPostgresSessionBindingUnsupported indicates that the active
	// authenticate flow cannot persist a live PostgreSQL SessionBinding.
	ErrPostgresSessionBindingUnsupported = errors.New("postgres session bindings require the stateful authenticate flow")
	// ErrPostgresSessionBindingInvalidSession indicates that the supplied
	// signed handle no longer names the same live databroker session.
	ErrPostgresSessionBindingInvalidSession = errors.New("postgres session binding session is invalid")
)

// CreatePostgresSessionBinding validates the live web session and creates a
// route-scoped, short-lived ProtocolPostgres binding. It deliberately does not
// create an IdentityBinding.
func (s *Stateful) CreatePostgresSessionBinding(
	ctx context.Context,
	h *session.Handle,
	expectedIDP, bindingID, routeHostname string,
	certificateExpiresAt time.Time,
) (*session.SessionBinding, error) {
	var err error
	routeHostname, err = postgresidentity.ValidateRouteHostname(routeHostname)
	if err != nil {
		return nil, ErrPostgresSessionBindingInvalidSession
	}
	if h == nil || h.GetId() == "" || h.GetUserId() == "" || h.GetIdentityProviderId() == "" {
		return nil, ErrPostgresSessionBindingInvalidSession
	}
	if bindingID == "" || routeHostname == "" || expectedIDP == "" || h.GetIdentityProviderId() != expectedIDP {
		return nil, ErrPostgresSessionBindingInvalidSession
	}

	resp, err := s.dataBrokerClient.Get(ctx, &databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(session.Session)),
		Id:   h.GetId(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPostgresSessionBindingInvalidSession, err)
	}
	if resp.GetRecord() == nil || resp.GetRecord().GetDeletedAt() != nil {
		return nil, ErrPostgresSessionBindingInvalidSession
	}
	var webSession session.Session
	if err := resp.GetRecord().GetData().UnmarshalTo(&webSession); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPostgresSessionBindingInvalidSession, err)
	}
	if webSession.GetId() != h.GetId() ||
		webSession.GetUserId() != h.GetUserId() ||
		webSession.GetIdpId() != h.GetIdentityProviderId() ||
		webSession.GetIdpId() != expectedIDP {
		return nil, ErrPostgresSessionBindingInvalidSession
	}
	if err := webSession.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPostgresSessionBindingInvalidSession, err)
	}

	now := timeNow()
	expiresAt := postgresSessionBindingExpiry(now, certificateExpiresAt, webSession.GetExpiresAt())
	if !expiresAt.After(now) {
		return nil, ErrPostgresSessionBindingInvalidSession
	}

	binding := &session.SessionBinding{
		Protocol:  session.ProtocolPostgres,
		SessionId: webSession.GetId(),
		UserId:    webSession.GetUserId(),
		IssuedAt:  timestamppb.New(now),
		ExpiresAt: timestamppb.New(expiresAt),
		Details:   map[string]string{postgresidentity.DetailRouteHostname: routeHostname},
	}
	if err := binding.GetIssuedAt().CheckValid(); err != nil {
		return nil, err
	}
	if err := binding.GetExpiresAt().CheckValid(); err != nil {
		return nil, err
	}
	if _, err := s.dataBrokerClient.Put(ctx, &databroker.PutRequest{Records: []*databroker.Record{{
		Type: grpcutil.GetTypeURL(binding),
		Id:   bindingID,
		Data: protoutil.NewAny(binding),
	}}}); err != nil {
		return nil, fmt.Errorf("create postgres session binding: %w", err)
	}
	return binding, nil
}

func postgresSessionBindingExpiry(
	now, certificateExpiresAt time.Time,
	sessionExpiresAt *timestamppb.Timestamp,
) time.Time {
	expiresAt := earlierTime(certificateExpiresAt, now.Add(time.Hour))
	if sessionExpiresAt != nil && sessionExpiresAt.AsTime().Year() > 1970 {
		expiresAt = earlierTime(expiresAt, sessionExpiresAt.AsTime())
	}
	return expiresAt
}

func earlierTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// CreatePostgresSessionBinding is unavailable in stateless authenticate mode
// because no live databroker session can back the binding.
func (s *Stateless) CreatePostgresSessionBinding(
	context.Context,
	*session.Handle,
	string, string, string,
	time.Time,
) (*session.SessionBinding, error) {
	return nil, ErrPostgresSessionBindingUnsupported
}
