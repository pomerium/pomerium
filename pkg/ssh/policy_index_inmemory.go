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
	state     inMemoryIndexerState
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

type inMemoryIndexerState struct {
	KnownStreams           map[uint64]*knownStream
	KnownSessions          map[string]*knownSession
	EnabledStaticPorts     []uint
	AllTunnelEnabledRoutes []portforward.RouteInfo
}

func (i *InMemoryPolicyIndexer) recomputeSessionAuthorizedRoutes(ctx context.Context, session *knownSession) {
	var authorizedRoutes []portforward.RouteInfo
	if session.Record != nil && session.AuthRequest != nil {
		authorizedRoutes = make([]portforward.RouteInfo, 0, len(session.AuthorizedRoutes))
		for _, route := range i.state.AllTunnelEnabledRoutes {
			result, err := i.evaluator.EvaluateUpstreamTunnel(ctx, *session.AuthRequest, route.Policy)
			if err == nil && result.Allow.Value && !result.Deny.Value {
				authorizedRoutes = append(authorizedRoutes, route)
			}
		}
	}
	if len(session.AuthorizedRoutes) == 0 && len(authorizedRoutes) == 0 {
		// session record not received yet, or no auth requests made
		return
	} else if len(session.AuthorizedRoutes) > 0 && len(authorizedRoutes) == 0 {
		session.AuthorizedRoutes = authorizedRoutes
		for streamID := range session.Streams {
			if stream, ok := i.state.KnownStreams[streamID]; ok && stream.Subscriber != nil {
				stream.Subscriber.UpdateAuthorizedRoutes(session.AuthorizedRoutes)
			}
		}
	} else {
		session.AuthorizedRoutes = authorizedRoutes
		for streamID := range session.Streams {
			if stream, ok := i.state.KnownStreams[streamID]; ok && stream.Subscriber != nil {
				stream.Subscriber.UpdateAuthorizedRoutes(session.AuthorizedRoutes)
			}
		}
	}
}

func (i *InMemoryPolicyIndexer) Run(ctx context.Context) error {
	i.state = inMemoryIndexerState{
		KnownStreams:  map[uint64]*knownStream{},
		KnownSessions: map[string]*knownSession{},
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
				stream, ok := i.state.KnownStreams[event.streamID]
				if !ok {
					stream = &knownStream{
						SessionID: event.authRequest.SessionID,
					}
					i.state.KnownStreams[event.streamID] = stream
				} else {
					stream.SessionID = event.authRequest.SessionID
				}
				session, ok := i.state.KnownSessions[event.authRequest.SessionID]
				if !ok {
					session = &knownSession{
						Streams: map[uint64]struct{}{event.streamID: {}},
					}
					i.state.KnownSessions[event.authRequest.SessionID] = session
				} else {
					session.Streams[event.streamID] = struct{}{}
				}
				if len(i.state.EnabledStaticPorts) > 0 && stream.Subscriber != nil {
					stream.Subscriber.UpdateEnabledStaticPorts(i.state.EnabledStaticPorts)
				}
				if session.AuthRequest == nil {
					// If the session is not known from a previous stream, compute its
					// authorized routes now. We don't need to do this if e.g. the same
					// user disconnects and reconnects with the same (valid) session.
					reqCopy := event.authRequest
					session.AuthRequest = &reqCopy
					i.recomputeSessionAuthorizedRoutes(ctx, session)
				} else if *session.AuthRequest != event.authRequest {
					panic("bug: inconsistent session auth state")
				} else {
					if stream.Subscriber != nil && len(session.AuthorizedRoutes) > 0 {
						stream.Subscriber.UpdateAuthorizedRoutes(session.AuthorizedRoutes)
					}
				}
			case streamAddEvent:
				if stream, ok := i.state.KnownStreams[event.streamID]; ok {
					if stream.Subscriber != nil {
						panic(fmt.Sprintf("bug: attempted to index stream %d twice", event.streamID))
					}
					stream.Subscriber = event.sub
					if len(i.state.EnabledStaticPorts) > 0 {
						stream.Subscriber.UpdateEnabledStaticPorts(i.state.EnabledStaticPorts)
					}
					if stream.SessionID != "" {
						if session, ok := i.state.KnownSessions[stream.SessionID]; ok {
							if len(session.AuthorizedRoutes) > 0 {
								stream.Subscriber.UpdateAuthorizedRoutes(session.AuthorizedRoutes)
							}
						}
					}
				} else {
					i.state.KnownStreams[event.streamID] = &knownStream{
						Subscriber: event.sub,
					}
				}

			case streamRemoveEvent:
				if stream, ok := i.state.KnownStreams[event.streamID]; ok {
					stream.Subscriber.UpdateEnabledStaticPorts(nil)
					if stream.SessionID != "" {
						if session, ok := i.state.KnownSessions[stream.SessionID]; ok {
							if len(session.AuthorizedRoutes) > 0 {
								stream.Subscriber.UpdateAuthorizedRoutes(nil)
							}
							delete(session.Streams, event.streamID)
							if session.Record == nil && len(session.Streams) == 0 {
								// There are no remaining references to this session, so it can
								// be untracked
								delete(i.state.KnownSessions, stream.SessionID)
							}
						}
					}
					// stream IDs are never seen again once removed
					delete(i.state.KnownStreams, event.streamID)
				}
			case sessionCreatedEvent:
				if session, ok := i.state.KnownSessions[event.session.Id]; ok {
					session.Record = event.session
					i.recomputeSessionAuthorizedRoutes(ctx, session)
				} else {
					i.state.KnownSessions[event.session.Id] = &knownSession{
						Record:  event.session,
						Streams: map[uint64]struct{}{},
					}
				}
			case sessionDeletedEvent:
				if session, ok := i.state.KnownSessions[event.sessionID]; ok {
					session.Record = nil
					i.recomputeSessionAuthorizedRoutes(ctx, session)
					if len(session.Streams) == 0 {
						// If there are any streams referencing this session, it should be
						// untracked only once those streams exit
						delete(i.state.KnownSessions, event.sessionID)
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
				if !slices.Equal(i.state.EnabledStaticPorts, allowedStaticPorts) {
					i.state.EnabledStaticPorts = allowedStaticPorts
					for _, stream := range i.state.KnownStreams {
						if stream.SessionID != "" && stream.Subscriber != nil {
							stream.Subscriber.UpdateEnabledStaticPorts(i.state.EnabledStaticPorts)
						}
					}
				}

				clear(i.state.AllTunnelEnabledRoutes)
				i.state.AllTunnelEnabledRoutes = i.state.AllTunnelEnabledRoutes[:0]
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
					i.state.AllTunnelEnabledRoutes = append(i.state.AllTunnelEnabledRoutes, info)
				}

				for _, session := range i.state.KnownSessions {
					i.recomputeSessionAuthorizedRoutes(ctx, session)
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
