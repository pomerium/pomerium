package ssh

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"slices"

	"github.com/google/go-cmp/cmp"
	lru "github.com/hashicorp/golang-lru/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
	"github.com/pomerium/protoutil/messages"
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
}

type sessionCreatedEvent struct {
	session *session.Session
}

type sessionDeletedEvent struct {
	sessionID string
}

type shutdownEvent struct{}

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

type knownAuthRequest struct {
	AuthRequest
	activeStreams map[uint64]struct{}

	onActive        func()
	onInactive      func()
	onStreamKnown   func(uint64)
	onStreamRemoved func(uint64)
}

func (kr *knownAuthRequest) ActiveStreams() iter.Seq[uint64] {
	return maps.Keys(kr.activeStreams)
}

func (kr *knownAuthRequest) IsActive() bool {
	return len(kr.activeStreams) > 0
}

func (kr *knownAuthRequest) AddActiveStream(streamID uint64) {
	kr.activeStreams[streamID] = struct{}{}
	kr.onStreamKnown(streamID)
	if len(kr.activeStreams) == 1 {
		kr.onActive()
	}
}

func (kr *knownAuthRequest) RemoveActiveStream(streamID uint64) {
	delete(kr.activeStreams, streamID)
	kr.onStreamRemoved(streamID)
	if len(kr.activeStreams) == 0 {
		kr.onInactive()
	}
}

// this is a separate struct so it can be updated in-place in the lru without
// affecting recentness
type authorizedRoutesList struct {
	Entries []portforward.RouteInfo
}

type authorizedRoutesCache struct {
	active     map[*knownAuthRequest]*authorizedRoutesList
	byStreamID map[uint64]*knownAuthRequest

	standby *lru.Cache[*knownAuthRequest, *authorizedRoutesList]
}

func (c *authorizedRoutesCache) NewKey(authReq AuthRequest, streamID uint64) *knownAuthRequest {
	kr := &knownAuthRequest{
		AuthRequest:   authReq,
		activeStreams: map[uint64]struct{}{},
	}
	kr.onActive = func() {
		if routes, ok := c.standby.Get(kr); ok {
			c.standby.Remove(kr)
			c.active[kr] = routes
		}
	}
	kr.onInactive = func() {
		if active, ok := c.active[kr]; ok {
			delete(c.active, kr)
			c.standby.Add(kr, active)
		}
	}
	kr.onStreamKnown = func(streamID uint64) {
		c.byStreamID[streamID] = kr
	}
	kr.onStreamRemoved = func(streamID uint64) {
		if c.byStreamID[streamID] != kr {
			panic("bug: invalid state")
		}
		delete(c.byStreamID, streamID)
	}
	kr.onStreamKnown(streamID) // added, but not active yet
	return kr
}

// Yields all active keys in a random order, followed by all inactive keys
// from newest to oldest
func (c *authorizedRoutesCache) Keys() iter.Seq[*knownAuthRequest] {
	return func(yield func(*knownAuthRequest) bool) {
		for k := range c.active {
			if !yield(k) {
				return
			}
		}
		for _, k := range slices.Backward(c.standby.Keys()) {
			if !yield(k) {
				return
			}
		}
	}
}

// Returns cached route entries for an auth request. The auth request must be
// active (have at least one active stream), otherwise it will be reported as
// not found.
func (c *authorizedRoutesCache) Get(knownReq *knownAuthRequest) ([]portforward.RouteInfo, bool) {
	if active, ok := c.active[knownReq]; ok {
		return active.Entries, true
	}
	return nil, false
}

func (c *authorizedRoutesCache) FindKey(request AuthRequest) *knownAuthRequest {
	for k := range c.active {
		if k.AuthRequest == request {
			return k
		}
	}
	for _, k := range c.standby.Keys() {
		if k.AuthRequest == request {
			return k
		}
	}
	return nil
}

func (c *authorizedRoutesCache) FindKeyForStream(streamID uint64) *knownAuthRequest {
	return c.byStreamID[streamID]
}

func (c *authorizedRoutesCache) StreamCount() int {
	return len(c.byStreamID)
}

func (c *authorizedRoutesCache) Update(k *knownAuthRequest, v []portforward.RouteInfo) {
	if l, ok := c.active[k]; ok {
		l.Entries = v
	} else if l, ok := c.standby.Peek(k); ok {
		l.Entries = v
	} else {
		if k.IsActive() {
			// start in active
			c.active[k] = &authorizedRoutesList{Entries: v}
		} else {
			// start in standby
			c.standby.Add(k, &authorizedRoutesList{Entries: v})
		}
	}
}

func (c *authorizedRoutesCache) Peek(k *knownAuthRequest) ([]portforward.RouteInfo, bool) {
	if active, ok := c.active[k]; ok {
		return active.Entries, true
	} else if inactive, ok := c.standby.Peek(k); ok {
		return inactive.Entries, true
	}
	return nil, false
}

func newAuthorizedRoutesCache(ctx context.Context) *authorizedRoutesCache {
	onEvict := func(k *knownAuthRequest, v *authorizedRoutesList) {
		log.Ctx(ctx).Debug().
			Str("session-id", k.SessionID).
			Int("cached-routes", len(v.Entries)).
			Msg("policy indexer: evicting unused auth request")
	}
	cache, err := lru.NewWithEvict(MaxCachedAuthRequestsPerSession, onEvict)
	if err != nil {
		panic(err)
	}
	return &authorizedRoutesCache{
		active:     map[*knownAuthRequest]*authorizedRoutesList{},
		byStreamID: map[uint64]*knownAuthRequest{},
		standby:    cache,
	}
}

type knownSession struct {
	Record *session.Session

	// Cached list of successful auth requests. These will share the same session
	// ID, but other parameters in the AuthRequest may differ.
	AuthorizedRoutesCache *authorizedRoutesCache
}

type knownRoute struct {
	Info  portforward.RouteInfo
	Route *config.Policy
}

type inMemoryIndexerState struct {
	KnownStreams           map[uint64]*knownStream
	KnownSessions          map[string]*knownSession
	EnabledStaticPorts     []uint
	AllTunnelEnabledRoutes []knownRoute
}

const MaxCachedAuthRequestsPerSession = 5

func (i *InMemoryPolicyIndexer) recomputeSessionAuthorizedRoutes(ctx context.Context, session *knownSession, authRequest *knownAuthRequest) {
	var updatedAuthorizedRoutes []knownRoute
	existingRoutes, hasExistingRoutes := session.AuthorizedRoutesCache.Peek(authRequest)
	numExistingAuthorizedRoutes := len(existingRoutes)
	if session.Record != nil {
		updatedAuthorizedRoutes = make([]knownRoute, 0, numExistingAuthorizedRoutes)
		for _, route := range i.state.AllTunnelEnabledRoutes {
			result, err := i.evaluator.EvaluateUpstreamTunnel(ctx, authRequest.AuthRequest, route.Route)
			if err != nil {
				log.Ctx(ctx).Err(err).
					Str("route", route.Info.Hostname).
					Msg("error evaluating upstream tunnel policy")
				continue
			}
			if result.Allow.Value && !result.Deny.Value {
				updatedAuthorizedRoutes = append(updatedAuthorizedRoutes, route)
			}
		}
	}

	if numExistingAuthorizedRoutes == 0 && len(updatedAuthorizedRoutes) == 0 {
		// session record not received yet, or no auth requests made
		if !hasExistingRoutes {
			session.AuthorizedRoutesCache.Update(authRequest, nil)
		}
		return
	} else if numExistingAuthorizedRoutes > 0 && len(updatedAuthorizedRoutes) == 0 {
		session.AuthorizedRoutesCache.Update(authRequest, nil)
		for streamID := range authRequest.ActiveStreams() {
			if stream, ok := i.state.KnownStreams[streamID]; ok && stream.Subscriber != nil {
				log.Ctx(ctx).Debug().
					Uint64("stream-id", streamID).
					Str("session-id", stream.SessionID).
					Msgf("clearing authorized routes for stream")
				stream.Subscriber.UpdateAuthorizedRoutes(nil)
			}
		}
	} else {
		routeInfos := make([]portforward.RouteInfo, len(updatedAuthorizedRoutes))
		for i, ar := range updatedAuthorizedRoutes {
			routeInfos[i] = ar.Info
		}
		session.AuthorizedRoutesCache.Update(authRequest, routeInfos)
		for streamID := range authRequest.ActiveStreams() {
			if stream, ok := i.state.KnownStreams[streamID]; ok && stream.Subscriber != nil {
				log.Ctx(ctx).Debug().
					Uint64("stream-id", streamID).
					Str("session-id", stream.SessionID).
					Int("routes", len(routeInfos)).
					Msgf("updating authorized routes for stream")
				stream.Subscriber.UpdateAuthorizedRoutes(routeInfos)
			}
		}
	}
}

func (i *InMemoryPolicyIndexer) Run(ctx context.Context) error {
	i.state = inMemoryIndexerState{
		KnownStreams:  map[uint64]*knownStream{},
		KnownSessions: map[string]*knownSession{},
	}

	log.Ctx(ctx).Debug().Msg("starting in-memory policy indexer")
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case event := <-i.eventsC:
			switch event := event.(type) {
			case shutdownEvent:
				log.Ctx(ctx).Debug().Msg("policy indexer: shutdown complete")
				return nil
			case streamAuthenticatedEvent:
				lg := log.Ctx(ctx).With().
					Uint64("stream-id", event.streamID).
					Str("session-id", event.authRequest.SessionID).
					Str("event", "stream_authenticated").
					Logger()
				stream, ok := i.state.KnownStreams[event.streamID]
				if !ok {
					lg.Debug().Msg("policy indexer: tracking new stream")
					stream = &knownStream{
						SessionID: event.authRequest.SessionID,
					}
					i.state.KnownStreams[event.streamID] = stream
				} else {
					lg.Debug().Msg("policy indexer: tracked stream authenticated")
					stream.SessionID = event.authRequest.SessionID
				}
				session, ok := i.state.KnownSessions[event.authRequest.SessionID]
				if !ok {
					lg.Debug().Msg("policy indexer: tracking new session")

					session = &knownSession{
						AuthorizedRoutesCache: newAuthorizedRoutesCache(ctx),
					}
					i.state.KnownSessions[event.authRequest.SessionID] = session
				}
				if len(i.state.EnabledStaticPorts) > 0 && stream.Subscriber != nil {
					stream.Subscriber.UpdateEnabledStaticPorts(i.state.EnabledStaticPorts)
				}

				knownReq := session.AuthorizedRoutesCache.FindKey(event.authRequest)
				if knownReq == nil {
					knownReq = session.AuthorizedRoutesCache.NewKey(event.authRequest, event.streamID)
					if stream.Subscriber != nil {
						knownReq.AddActiveStream(event.streamID)
					}
					lg.Debug().Msg("policy indexer: computing session authorized routes")
					// If the session is not known from a previous stream, compute its
					// authorized routes now. We don't need to do this if e.g. the same
					// user disconnects and reconnects with the same (valid) session
					// and auth request details
					// Note: this will add to the session's AuthorizedRoutesCache
					i.recomputeSessionAuthorizedRoutes(ctx, session, knownReq)
				} else {
					lg.Debug().Msg("policy indexer: using cached auth request")
					if stream.Subscriber != nil {
						knownReq.AddActiveStream(event.streamID)
						cachedAuthorizedRoutes, ok := session.AuthorizedRoutesCache.Get(knownReq)
						if ok && len(cachedAuthorizedRoutes) > 0 {
							log.Ctx(ctx).Debug().
								Uint64("stream-id", event.streamID).
								Str("session-id", stream.SessionID).
								Int("routes", len(cachedAuthorizedRoutes)).
								Msgf("updating authorized routes for stream (cached)")
							stream.Subscriber.UpdateAuthorizedRoutes(cachedAuthorizedRoutes)
						}
					}
				}
			case streamAddEvent:
				lg := log.Ctx(ctx).With().
					Uint64("stream-id", event.streamID).
					Str("event", "stream_add").
					Logger()
				if stream, ok := i.state.KnownStreams[event.streamID]; ok {
					lg.Debug().Msg("policy indexer: tracked stream updated")
					if stream.Subscriber != nil {
						panic(fmt.Sprintf("bug: attempted to index stream %d twice", event.streamID))
					}
					stream.Subscriber = event.sub
					if stream.SessionID != "" {
						session := i.state.KnownSessions[stream.SessionID] // must be non-nil
						if len(i.state.EnabledStaticPorts) > 0 {
							stream.Subscriber.UpdateEnabledStaticPorts(i.state.EnabledStaticPorts)
						}
						authReq := session.AuthorizedRoutesCache.FindKeyForStream(event.streamID)
						if authReq != nil {
							authReq.AddActiveStream(event.streamID)
							cachedAuthorizedRoutes, ok := session.AuthorizedRoutesCache.Get(authReq)
							if ok && len(cachedAuthorizedRoutes) > 0 {
								log.Ctx(ctx).Debug().
									Uint64("stream-id", event.streamID).
									Str("session-id", stream.SessionID).
									Int("routes", len(cachedAuthorizedRoutes)).
									Msgf("updating authorized routes for stream (cached)")
								stream.Subscriber.UpdateAuthorizedRoutes(cachedAuthorizedRoutes)
							}
						}
					}
				} else {
					lg.Debug().Msg("policy indexer: tracking new stream")
					i.state.KnownStreams[event.streamID] = &knownStream{
						Subscriber: event.sub,
					}
				}
			case streamRemoveEvent:
				lg := log.Ctx(ctx).With().Uint64("stream-id", event.streamID).Logger()
				if stream, ok := i.state.KnownStreams[event.streamID]; ok {
					lg.Debug().Msg("policy indexer: tracked stream removed")
					if stream.SessionID != "" {
						session := i.state.KnownSessions[stream.SessionID] // must be non-nil
						if len(i.state.EnabledStaticPorts) > 0 {
							// Note: if static ports were removed after having been enabled
							// previously, we would have already notified this subscriber
							// at the time the ports were removed.
							if stream.Subscriber == nil {
								panic(fmt.Sprintf("bug: stream %d removed before it was added", event.streamID))
							}
							stream.Subscriber.UpdateEnabledStaticPorts(nil)
						}
						if knownAuthReq := session.AuthorizedRoutesCache.FindKeyForStream(event.streamID); knownAuthReq != nil {
							if routes, ok := session.AuthorizedRoutesCache.Get(knownAuthReq); ok && len(routes) > 0 {
								log.Ctx(ctx).Debug().
									Uint64("stream-id", event.streamID).
									Str("session-id", stream.SessionID).
									Msgf("clearing authorized routes for stream")
								stream.Subscriber.UpdateAuthorizedRoutes(nil)
							}
							knownAuthReq.RemoveActiveStream(event.streamID)
						}
						if session.Record == nil && session.AuthorizedRoutesCache.StreamCount() == 0 {
							lg.Debug().Str("session-id", stream.SessionID).
								Msg("policy indexer: deleted session has no more references, removing from cache")
							// There are no remaining references to this session, so it can
							// be untracked
							delete(i.state.KnownSessions, stream.SessionID)
						}
					} else {
						lg.Debug().Str("session-id", "(none)").
							Msg("policy indexer: stream removed")
					}
					// stream IDs are never seen again once removed
					delete(i.state.KnownStreams, event.streamID)
				} else {
					lg.Warn().Msg("policy indexer: tried to remove unknown stream")
				}
			case sessionCreatedEvent:
				lg := log.Ctx(ctx).With().
					Str("session-id", event.session.Id).
					Str("event", "session_created").
					Logger()
				if session, ok := i.state.KnownSessions[event.session.Id]; ok {
					rebuildRoutes := true
					if session.Record != nil {
						if event.session.Version == "" {
							lg.Warn().Msg("session is missing version")
						}
						if session.Record.Version == event.session.Version {
							lg.Warn().Msg("session updated but record version did not change")
						}
						if sessionsEquivalent(session.Record, event.session) {
							rebuildRoutes = false
						}
					}
					session.Record = event.session
					if rebuildRoutes {
						lg.Debug().Msg("policy indexer: rebuilding routes index for modified session")
						for authReq := range session.AuthorizedRoutesCache.Keys() {
							i.recomputeSessionAuthorizedRoutes(ctx, session, authReq)
						}
					}
				} else {
					lg.Debug().Msg("policy indexer: tracking new session")
					i.state.KnownSessions[event.session.Id] = &knownSession{
						Record:                event.session,
						AuthorizedRoutesCache: newAuthorizedRoutesCache(ctx),
					}
				}
			case sessionDeletedEvent:
				lg := log.Ctx(ctx).With().
					Str("session-id", event.sessionID).
					Str("event", "session_deleted").
					Logger()
				if session, ok := i.state.KnownSessions[event.sessionID]; ok {
					lg.Debug().Msg("policy indexer: tracked session removed")
					session.Record = nil
					for authReq := range session.AuthorizedRoutesCache.Keys() {
						i.recomputeSessionAuthorizedRoutes(ctx, session, authReq)
						// sanity check
						if routes, ok := session.AuthorizedRoutesCache.Peek(authReq); ok && len(routes) != 0 {
							panic("bug: clearing session authorized requests failed")
						}
					}
					if session.AuthorizedRoutesCache.StreamCount() == 0 {
						// If there are any streams referencing this session, it should be
						// untracked only once those streams exit
						delete(i.state.KnownSessions, event.sessionID)
					}
				} else {
					lg.Warn().Msg("policy indexer: tried to remove unknown session")
				}
			case configUpdateEvent:
				lg := log.Ctx(ctx).With().Str("event", "config_update").Logger()

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

				i.state.AllTunnelEnabledRoutes = i.state.AllTunnelEnabledRoutes[:0]
				for route := range options.GetAllPolicies() {
					if route.UpstreamTunnel == nil {
						continue
					}
					info := portforward.RouteInfo{
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
					i.state.AllTunnelEnabledRoutes = append(i.state.AllTunnelEnabledRoutes, knownRoute{
						Info:  info,
						Route: route,
					})
				}

				lg.Debug().Msgf("policy indexer: rebuilding cache for %d sessions", len(i.state.KnownSessions))
				for _, session := range i.state.KnownSessions {
					for authReq := range session.AuthorizedRoutesCache.Keys() {
						i.recomputeSessionAuthorizedRoutes(ctx, session, authReq)
					}
				}
			}
		}
	}
}

var sessionAccessedAtField = func() protoreflect.FieldDescriptor {
	f := messages.FieldByName[*session.Session]("accessed_at")
	if f == nil {
		panic("could not find field 'accessed_at' in session.Session")
	}
	return f
}()

var sessionVersionField = func() protoreflect.FieldDescriptor {
	f := messages.FieldByName[*session.Session]("version")
	if f == nil {
		panic("could not find field 'version' in session.Session")
	}
	return f
}()

func sessionsEquivalent(a *session.Session, b *session.Session) bool {
	return cmp.Equal(a, b, protocmp.Transform(), protocmp.IgnoreDescriptors(sessionAccessedAtField, sessionVersionField))
}

func (i *InMemoryPolicyIndexer) Shutdown() {
	i.eventsC <- shutdownEvent{}
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
func (i *InMemoryPolicyIndexer) RemoveStream(streamID uint64) {
	i.eventsC <- streamRemoveEvent{
		streamID: streamID,
	}
}

var _ PolicyIndexer = (*InMemoryPolicyIndexer)(nil)
