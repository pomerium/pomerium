package ssh

import (
	"context"
	"slices"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
	"google.golang.org/protobuf/proto"
)

type streamAuthenticatedEvent struct {
	streamID    uint64
	authRequest Request
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
	databrokerClient databroker.DataBrokerServiceClient
	evaluator        Evaluator

	eventsC chan any
}

func NewInMemoryPolicyIndexer(client databroker.DataBrokerServiceClient, eval Evaluator) *InMemoryPolicyIndexer {
	return &InMemoryPolicyIndexer{
		databrokerClient: client,
		evaluator:        eval,
		eventsC:          make(chan any, 1024),
	}
}

type knownStream struct {
	Subscriber PolicyIndexSubscriber
	SessionID  string
}

type knownSession struct {
	Record      *session.Session
	AuthRequest *Request
	Streams     map[uint64]struct{}

	AuthorizedRoutes []portforward.RouteInfo
	EvaluateResults  map[string]bool
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
				Streams:         map[uint64]struct{}{streamID: {}},
				EvaluateResults: map[string]bool{},
			}
			state.KnownSessions[sessionID] = session
		} else {
			session.Streams[streamID] = struct{}{}
		}
		return stream, session
	}
	updateSessionAuthorizedRoutes := func(streamID uint64, stream *knownStream, session *knownSession) {
		// evaluate all routes
		authorizedRoutes := make([]portforward.RouteInfo, 0, len(session.AuthorizedRoutes))
		for _, route := range state.AllTunnelEnabledRoutes {
			// check for previous result
			var authorized bool
			if res, ok := session.EvaluateResults[route.RouteID]; ok {
				authorized = res
			} else {
				result, err := i.evaluator.EvaluateSSH(ctx, streamID, *session.AuthRequest, true)
				if err == nil && result.Allow.Value && !result.Deny.Value {
					authorized = true
				}
				// cache the result
				session.EvaluateResults[route.RouteID] = authorized
			}
			if authorized {
				authorizedRoutes = append(authorizedRoutes, route)
			}
		}
		session.AuthorizedRoutes = authorizedRoutes

		if stream.Subscriber != nil {
			stream.Subscriber.UpdateAuthorizedRoutes(authorizedRoutes)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case event := <-i.eventsC:
			switch event := event.(type) {
			case streamAuthenticatedEvent:
				stream, session := trackStreamSessionAssociation(event.streamID, event.authRequest.SessionID)
				session.AuthRequest = &event.authRequest
				if session.Record != nil {
					stream.Subscriber.UpdateEnabledStaticPorts(state.EnabledStaticPorts)
					updateSessionAuthorizedRoutes(event.streamID, stream, session)
				}
			case streamAddEvent:
				if stream, ok := state.KnownStreams[event.streamID]; ok {
					stream.Subscriber = event.sub
					if stream.SessionID != "" {
						_, session := trackStreamSessionAssociation(event.streamID, stream.SessionID)
						if session.Record != nil && session.AuthRequest != nil {
							stream.Subscriber.UpdateEnabledStaticPorts(state.EnabledStaticPorts)
							updateSessionAuthorizedRoutes(event.streamID, stream, session)
						}
					}
				} else {
					state.KnownStreams[event.streamID] = &knownStream{
						Subscriber: event.sub,
					}
				}
			case streamRemoveEvent:
				if stream, ok := state.KnownStreams[event.streamID]; ok {
					stream.Subscriber.UpdateAuthorizedRoutes(nil)
					stream.Subscriber.UpdateEnabledStaticPorts(nil)
					if stream.SessionID != "" {
						if session, ok := state.KnownSessions[stream.SessionID]; ok {
							delete(session.Streams, event.streamID)
							if session.Record == nil && len(session.Streams) == 0 {
								delete(state.KnownSessions, stream.SessionID)
							}
						}
					}
					// stream IDs are never seen again once removed
					delete(state.KnownStreams, event.streamID)
				}
			case sessionCreatedEvent:
				if session, ok := state.KnownSessions[event.session.Id]; ok {
					// this also gets called on record updates so it should be idempotent
					initial := session.Record == nil
					session.Record = event.session
					for streamID := range session.Streams {
						stream, _ := trackStreamSessionAssociation(streamID, session.Record.Id)
						if stream.Subscriber != nil && session.AuthRequest != nil {
							if initial {
								stream.Subscriber.UpdateEnabledStaticPorts(state.EnabledStaticPorts)
							}
							updateSessionAuthorizedRoutes(streamID, stream, session)
						}
					}
				} else {
					state.KnownSessions[event.session.Id] = &knownSession{
						Record:          event.session,
						Streams:         map[uint64]struct{}{},
						EvaluateResults: map[string]bool{},
					}
				}
			case sessionDeletedEvent:
				if session, ok := state.KnownSessions[event.sessionID]; ok {
					for streamID := range session.Streams {
						if stream, ok := state.KnownStreams[streamID]; ok {
							if stream.Subscriber != nil {
								stream.Subscriber.UpdateEnabledStaticPorts(nil)
								stream.Subscriber.UpdateAuthorizedRoutes(nil)
							}
						}
					}
					session.Record = nil
					if len(session.Streams) == 0 {
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
						RouteID:   route.MustRouteID(),
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

				for streamID, stream := range state.KnownStreams {
					if stream.SessionID == "" {
						continue
					}
					if session, ok := state.KnownSessions[stream.SessionID]; ok {
						if session.Record == nil || session.AuthRequest == nil {
							continue
						}

						updateSessionAuthorizedRoutes(streamID, stream, session)
					}
				}
			}
		}
	}
}

// OnStreamAuthenticated implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) OnStreamAuthenticated(streamID uint64, authRequest Request) {
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

// AddSubscriber implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) AddSubscriber(streamID uint64, sub PolicyIndexSubscriber) {
	i.eventsC <- streamAddEvent{
		streamID: streamID,
		sub:      sub,
	}
}

// RemoveSubscriber implements PolicyIndexer.
func (i *InMemoryPolicyIndexer) RemoveSubscriber(streamID uint64, sub PolicyIndexSubscriber) {
	i.eventsC <- streamRemoveEvent{
		streamID: streamID,
		sub:      sub,
	}
}

var _ PolicyIndexer = (*InMemoryPolicyIndexer)(nil)
