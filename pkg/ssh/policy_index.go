package ssh

import (
	"context"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

//go:generate go run go.uber.org/mock/mockgen -typed -destination ./mock/mock_policy_index.go . PolicyIndexSubscriber

type PolicyIndexSubscriber interface {
	UpdateEnabledStaticPorts(allowedStaticPorts []uint)
	UpdateAuthorizedRoutes(routes []portforward.RouteInfo)
}

type PolicyIndexer interface {
	Run(ctx context.Context) error
	ProcessConfigUpdate(cfg *config.Config)
	OnStreamAuthenticated(streamID uint64, req AuthRequest)
	OnSessionCreated(session *session.Session)
	OnSessionDeleted(sessionID string)
	AddStream(streamID uint64, sub PolicyIndexSubscriber)
	RemoveStream(streamID uint64, sub PolicyIndexSubscriber)
	Shutdown()
}
