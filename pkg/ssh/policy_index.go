package ssh

import (
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type PolicyIndexSubscriber interface {
	UpdateEnabledStaticPorts(allowedStaticPorts []uint)
	UpdateAuthorizedRoutes(routes []portforward.RouteInfo)
}

type PolicyIndexer interface {
	ProcessConfigUpdate(cfg *config.Config)
	OnStreamAuthenticated(streamID uint64, req AuthRequest)
	OnSessionCreated(session *session.Session)
	OnSessionDeleted(sessionID string)
	AddSubscriber(streamID uint64, sub PolicyIndexSubscriber)
	RemoveSubscriber(streamID uint64, sub PolicyIndexSubscriber)
}
