package ssh

import (
	"context"
	"fmt"
	"slices"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
	"google.golang.org/protobuf/proto"
)

type streamAuthenticatedEvent struct {
	streamID    uint64
	authRequest AuthRequest
}

type configUpdateEvent struct {
	config *config.Config
}

type streamAddEvent struct {
	streamID uint64
	sub      PolicyIndexSubscriber
}

type streamRemoveEvent struct {
	streamID uint64
	sub      PolicyIndexSubscriber
}

type sessionCreatedEvent struct {
	session *session.Session
}

type sessionDeletedEvent struct {
	sessionID string
}

type InMemoryPolicyIndexer struct {
	evaluator SSHEvaluator
	eventsC   chan any
}

func NewInMemoryPolicyIndexer(eval SSHEvaluator) *InMemoryPolicyIndexer {
	return &InMemoryPolicyIndexer{
		evaluator: eval,
		eventsC:   make(chan any, 1024),
	}
}

type knownStream struct {
	Subscriber PolicyIndexSubscriber
	SessionID  string
}

type knownSession struct {
	Record      *session.Session
	AuthRequest *AuthRequest
	Streams     map[uint64]struct{}

	AuthorizedRoutes []portforward.RouteInfo
}

type state struct {
	KnownStreams           map[uint64]*knownStream
	KnownSessions          map[string]*knownSession
	EnabledStaticPorts     []uint
	AllTunnelEnabledRoutes []portforward.RouteInfo
}

func (i *InMemoryPolicyIndexer) Run(ctx context.Context) error {
	state := state{
		KnownStreams:  map[uint64]*knownStream{},
		KnownSessions: map[string]*knownSession{},
	}
	trackStreamSessionAssociation := func(streamID uint64, sessionID string) (*knownStream, *knownSession) {
		stream, ok := state.KnownStreams[streamID]
		if !ok {
			stream = &knownStream{
				SessionID: sessionID,
			}
			state.KnownStreams[streamID] = stream
		} else {
			stream.SessionID = sessionID
		}
		session, ok := state.KnownSessions[sessionID]
		if !ok {
			session = &knownSession{
				Streams: map[uint64]struct{}{streamID: {}},
			}
			state.KnownSessions[sessionID] = session
		} else {
			session.Streams[streamID] = struct{}{}
		}
		return stream, session
	}
	recomputeSessionAuthorizedRoutes := func(session *knownSession) {
		authorizedRoutes := make([]portforward.RouteInfo, 0, len(session.AuthorizedRoutes))
		if session.Record != nil && session.AuthRequest != nil {
			for _, route := range state.AllTunnelEnabledRoutes {
				result, err := i.evaluator.EvaluateUpstreamTunnel(ctx, *session.AuthRequest, route.Policy)
				if err == nil && result.Allow.Value && !result.Deny.Value {
					authorizedRoutes = append(authorizedRoutes, route)
				}
			}
		}
		if len(session.AuthorizedRoutes) == len(authorizedRoutes) {
			anyChanged := false
			for i := range len(session.AuthorizedRoutes) {
				if session.AuthorizedRoutes[i].Policy != authorizedRoutes[i].Policy {
					anyChanged = true
					break
				}
			}
			if !anyChanged {
				return
			}
		}

		session.AuthorizedRoutes = authorizedRoutes
		for streamID := range session.Streams {
			if stream, ok := state.KnownStreams[streamID]; ok && stream.Subscriber != nil {
				stream.Subscriber.UpdateAuthorizedRoutes(session.AuthorizedRoutes)
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case event, ok := <-i.eventsC:
			if !ok {
				return nil
			}
			switch event := event.(type) {
			case streamAuthenticatedEvent:
				stream, session := trackStreamSessionAssociation(event.streamID, event.authRequest.SessionID)
				if len(state.EnabledStaticPorts) > 0 {
					stream.Subscriber.UpdateEnabledStaticPorts(state.EnabledStaticPorts)
				}
				if session.AuthRequest == nil {
					// If the session is not known from a previous stream, compute its
					// authorized routes now. We don't need to do this if e.g. the same
					// user disconnects and reconnects with the same (valid) session.
					reqCopy := event.authRequest
					session.AuthRequest = &reqCopy
					recomputeSessionAuthorizedRoutes(session)
				}
			case streamAddEvent:
				if _, ok := state.KnownStreams[event.streamID]; ok {
					panic(fmt.Sprintf("bug: attempted to index stream %d twice", event.streamID))
				}
				state.KnownStreams[event.streamID] = &knownStream{
					Subscriber: event.sub,
				}
			case streamRemoveEvent:
				if stream, ok := state.KnownStreams[event.streamID]; ok {
					stream.Subscriber.UpdateEnabledStaticPorts(nil)
					stream.Subscriber.UpdateAuthorizedRoutes(nil)
					stream.Subscriber = nil
					if stream.SessionID != "" {
						if session, ok := state.KnownSessions[stream.SessionID]; ok {
							delete(session.Streams, event.streamID)
							if session.Record == nil && len(session.Streams) == 0 {
								// There are no remaining references to this session, so it can
								// be untracked
								delete(state.KnownSessions, stream.SessionID)
							}
						}
					}
					// stream IDs are never seen again once removed
					delete(state.KnownStreams, event.streamID)
				}
			case sessionCreatedEvent:
				if session, ok := state.KnownSessions[event.session.Id]; ok {
					session.Record = event.session
					recomputeSessionAuthorizedRoutes(session)
				} else {
					state.KnownSessions[event.session.Id] = &knownSession{
						Record:  event.session,
						Streams: map[uint64]struct{}{},
					}
				}
			case sessionDeletedEvent:
				if session, ok := state.KnownSessions[event.sessionID]; ok {
					session.Record = nil
					recomputeSessionAuthorizedRoutes(session)
					if len(session.Streams) == 0 {
						// If there are any streams referencing this session, it should be
						// untracked only once those streams exit
						delete(state.KnownSessions, event.sessionID)
					}
				}
			case configUpdateEvent:
				options := event.config.Options
				// Update static ports
				const httpsPort = 443
				const sshPort = 22
				allowedStaticPorts := []uint{httpsPort}
				if options.SSHAddr != "" {
					allowedStaticPorts = append(allowedStaticPorts, sshPort)
				}
				if !slices.Equal(state.EnabledStaticPorts, allowedStaticPorts) {
					state.EnabledStaticPorts = allowedStaticPorts
					for _, stream := range state.KnownStreams {
						if stream.SessionID != "" {
							stream.Subscriber.UpdateEnabledStaticPorts(state.EnabledStaticPorts)
						}
					}
				}

				clear(state.AllTunnelEnabledRoutes)
				state.AllTunnelEnabledRoutes = state.AllTunnelEnabledRoutes[:0]
				for route := range options.GetAllPolicies() {
					if route.UpstreamTunnel == nil {
						continue
					}
					info := portforward.RouteInfo{
						Policy:    route,
						From:      route.From,
						To:        route.To,
						ClusterID: envoyconfig.GetClusterID(route),
					}
					u, err := urlutil.ParseAndValidateURL(route.From)
					if err != nil {
						continue
					}
					switch u.Scheme {
					case "https":
						info.Port = httpsPort
					case "ssh":
						info.Port = sshPort
					default:
						continue
					}
					info.Hostname = u.Hostname()
					state.AllTunnelEnabledRoutes = append(state.AllTunnelEnabledRoutes, info)
				}

				for _, session := range state.KnownSessions {
					recomputeSessionAuthorizedRoutes(session)
				}
			}
		}
	}
}

func (i *InMemoryPolicyIndexer) Shutdown() {
	close(i.eventsC)
}

// OnStreamAuthenticated implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) OnStreamAuthenticated(streamID uint64, authRequest AuthRequest) {
	i.eventsC <- streamAuthenticatedEvent{
		streamID:    streamID,
		authRequest: authRequest,
	}
}

// ProcessConfigUpdate implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) ProcessConfigUpdate(cfg *config.Config) {
	i.eventsC <- configUpdateEvent{
		config: cfg,
	}
}

// OnSessionCreated implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) OnSessionCreated(s *session.Session) {
	i.eventsC <- sessionCreatedEvent{
		session: proto.Clone(s).(*session.Session),
	}
}

// OnSessionDeleted implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) OnSessionDeleted(sessionID string) {
	i.eventsC <- sessionDeletedEvent{
		sessionID: sessionID,
	}
}

// AddStream implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) AddStream(streamID uint64, sub PolicyIndexSubscriber) {
	i.eventsC <- streamAddEvent{
		streamID: streamID,
		sub:      sub,
	}
}

// RemoveStream implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) RemoveStream(streamID uint64, sub PolicyIndexSubscriber) {
	i.eventsC <- streamRemoveEvent{
		streamID: streamID,
		sub:      sub,
	}
}

var _ PolicyIndexer = (*InMemoryPolicyIndexer)(nil)
