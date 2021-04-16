// Package xdsmgr implements a resource discovery manager for envoy.
package xdsmgr

import (
	"encoding/json"
	"errors"
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

var onHandleDeltaRequest = func(state *streamState) {}

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
		signal:    signal.New(),
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

	getDeltaResponse := func(typeURL string) *envoy_service_discovery_v3.DeltaDiscoveryResponse {
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

	handleDeltaRequest := func(req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
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
			bs, _ := json.Marshal(req.ErrorDetail.Details)
			log.Error().
				Err(errors.New(req.ErrorDetail.Message)).
				Int32("code", req.ErrorDetail.Code).
				RawJSON("details", bs).Msg("error applying configuration")
			// - set the client resource versions to the current resource versions
			state.clientResourceVersions = make(map[string]string)
			for _, resource := range mgr.resources[req.GetTypeUrl()] {
				state.clientResourceVersions[resource.Name] = resource.Version
			}
		case req.GetResponseNonce() == mgr.nonce:
			// an ACK for the last response
			// - set the client resource versions to the current resource versions
			state.clientResourceVersions = make(map[string]string)
			for _, resource := range mgr.resources[req.GetTypeUrl()] {
				state.clientResourceVersions[resource.Name] = resource.Version
			}
		default:
			// an ACK for a response that's not the last response
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
		for {
			var typeURLs []string
			select {
			case <-ctx.Done():
				return ctx.Err()
			case req := <-incoming:
				handleDeltaRequest(req)
				typeURLs = []string{req.GetTypeUrl()}
			case <-ch:
				mgr.mu.Lock()
				for typeURL := range mgr.resources {
					typeURLs = append(typeURLs, typeURL)
				}
				mgr.mu.Unlock()
			}

			for _, typeURL := range typeURLs {
				res := getDeltaResponse(typeURL)
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
	stream envoy_service_discovery_v3.AggregatedDiscoveryService_StreamAggregatedResourcesServer,
) error {
	return status.Errorf(codes.Unimplemented, "method StreamAggregatedResources not implemented")
}

// Update updates the state of resources. If any changes are made they will be pushed to any listening
// streams. For each TypeURL the list of resources should be the complete list of resources.
func (mgr *Manager) Update(resources map[string][]*envoy_service_discovery_v3.Resource) {
	mgr.mu.Lock()
	mgr.nonce = uuid.New().String()
	mgr.resources = resources
	mgr.mu.Unlock()

	mgr.signal.Broadcast()
}
