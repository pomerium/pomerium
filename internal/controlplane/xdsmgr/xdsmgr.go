// Package xdsmgr implements a resource discovery manager for envoy.
package xdsmgr

import (
	"context"
	"sync"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
)

type streamState struct {
	typeURL                string
	clientResourceVersions map[string]string
	unsubscribedResources  map[string]struct{}
}

var onHandleDeltaRequest = func(_ *streamState) {}

// A Manager manages xDS resources.
type Manager struct {
	signal *signal.Signal

	mu        sync.Mutex
	nonce     string
	resources map[string][]*envoy_service_discovery_v3.Resource
}

// NewManager creates a new Manager.
func NewManager(resources map[string][]*envoy_service_discovery_v3.Resource) *Manager {
	return &Manager{
		signal: signal.New(),

		nonce:     uuid.New().String(),
		resources: resources,
	}
}

// DeltaAggregatedResources implements the increment xDS server.
func (mgr *Manager) DeltaAggregatedResources(
	stream envoy_service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	ch := mgr.signal.Bind()
	defer mgr.signal.Unbind(ch)

	stateByTypeURL := map[string]*streamState{}

	getDeltaResponse := func(_ context.Context, typeURL string) *envoy_service_discovery_v3.DeltaDiscoveryResponse {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()

		state, ok := stateByTypeURL[typeURL]
		if !ok {
			return nil
		}

		res := &envoy_service_discovery_v3.DeltaDiscoveryResponse{
			TypeUrl: typeURL,
			Nonce:   mgr.nonce,
		}
		seen := map[string]struct{}{}
		for _, resource := range mgr.resources[typeURL] {
			seen[resource.Name] = struct{}{}
			if resource.Version != state.clientResourceVersions[resource.Name] {
				res.Resources = append(res.Resources, resource)
			}
		}
		for name := range state.clientResourceVersions {
			_, ok := seen[name]
			if !ok {
				res.RemovedResources = append(res.RemovedResources, name)
			}
		}

		if len(res.Resources) == 0 && len(res.RemovedResources) == 0 {
			return nil
		}

		return res
	}

	handleDeltaRequest := func(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()

		state, ok := stateByTypeURL[req.GetTypeUrl()]
		if !ok {
			// first time we've seen a message for this type URL.
			state = &streamState{
				typeURL:                req.GetTypeUrl(),
				clientResourceVersions: req.GetInitialResourceVersions(),
				unsubscribedResources:  make(map[string]struct{}),
			}
			if state.clientResourceVersions == nil {
				state.clientResourceVersions = make(map[string]string)
			}
			stateByTypeURL[req.GetTypeUrl()] = state
		}

		switch {
		case req.GetResponseNonce() == "":
			// neither an ACK or a NACK
		case req.GetErrorDetail() != nil:
			// a NACK
			// - set the client resource versions to the current resource versions
			state.clientResourceVersions = make(map[string]string)
			for _, resource := range mgr.resources[req.GetTypeUrl()] {
				state.clientResourceVersions[resource.Name] = resource.Version
			}
			logNACK(req)
		case req.GetResponseNonce() == mgr.nonce:
			// an ACK for the last response
			// - set the client resource versions to the current resource versions
			state.clientResourceVersions = make(map[string]string)
			for _, resource := range mgr.resources[req.GetTypeUrl()] {
				state.clientResourceVersions[resource.Name] = resource.Version
			}
			logACK(req)
		default:
			// an ACK for a response that's not the last response
			log.Debug(ctx).
				Str("type-url", req.GetTypeUrl()).
				Msg("xdsmgr: ack")
		}

		// update subscriptions
		for _, name := range req.GetResourceNamesSubscribe() {
			delete(state.unsubscribedResources, name)
		}
		for _, name := range req.GetResourceNamesUnsubscribe() {
			state.unsubscribedResources[name] = struct{}{}
			// from the docs:
			//   NOTE: the server must respond with all resources listed in
			//   resource_names_subscribe, even if it believes the client has
			//   the most recent version of them. The reason: the client may
			//   have dropped them, but then regained interest before it had
			//   a chance to send the unsubscribe message.
			// so we reset the version to treat it like a new version
			delete(state.clientResourceVersions, name)
		}

		onHandleDeltaRequest(state)
	}

	incoming := make(chan *envoy_service_discovery_v3.DeltaDiscoveryRequest)
	outgoing := make(chan *envoy_service_discovery_v3.DeltaDiscoveryResponse)
	eg, ctx := errgroup.WithContext(stream.Context())
	// 1. receive all incoming messages
	eg.Go(func() error {
		for {
			req, err := stream.Recv()
			if err != nil {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case incoming <- req:
			}
		}
	})
	// 2. handle incoming requests or resource changes
	eg.Go(func() error {
		changeCtx := ctx
		for {
			var typeURLs []string
			select {
			case <-ctx.Done():
				return ctx.Err()
			case req := <-incoming:
				handleDeltaRequest(changeCtx, req)
				typeURLs = []string{req.GetTypeUrl()}
			case changeCtx = <-ch:
				mgr.mu.Lock()
				for typeURL := range mgr.resources {
					typeURLs = append(typeURLs, typeURL)
				}
				mgr.mu.Unlock()
			}

			for _, typeURL := range typeURLs {
				res := getDeltaResponse(changeCtx, typeURL)
				if res == nil {
					continue
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				case outgoing <- res:
				}
			}
		}
	})
	// 3. send all outgoing messages
	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case res := <-outgoing:
				log.Debug(ctx).
					Str("type-url", res.GetTypeUrl()).
					Int("resource-count", len(res.GetResources())).
					Int("removed-resource-count", len(res.GetRemovedResources())).
					Msg("xdsmgr: sending resources")
				err := stream.Send(res)
				if err != nil {
					return err
				}
			}
		}
	})
	return eg.Wait()
}

// StreamAggregatedResources is not implemented.
func (mgr *Manager) StreamAggregatedResources(
	_ envoy_service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer,
) error {
	return status.Errorf(codes.Unimplemented, "method StreamAggregatedResources not implemented")
}

// Update updates the state of resources. If any changes are made they will be pushed to any listening
// streams. For each TypeURL the list of resources should be the complete list of resources.
func (mgr *Manager) Update(ctx context.Context, resources map[string][]*envoy_service_discovery_v3.Resource) {
	nonce := uuid.New().String()

	mgr.mu.Lock()
	mgr.nonce = nonce
	mgr.resources = resources
	mgr.mu.Unlock()

	mgr.signal.Broadcast(ctx)
}
