// Package xdsmgr implements a resource discovery manager for envoy.
package xdsmgr

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/health"
)

// streamState is what one stream has sent to envoy for one resource type.
type streamState struct {
	lastNonce string
	// clientResourceVersions is the version of each resource sent to envoy
	clientResourceVersions map[string]string
	// unsubscribedResources are the resources envoy asked not to be sent
	unsubscribedResources map[string]struct{}
}

// recordSent records the resources of a response as held by envoy. Envoy
// applies a response before it acknowledges it, so the ACKs do not tell what
// envoy holds. The record stays after a NACK, so a rejected resource is not
// re-sent until it changes.
func (s *streamState) recordSent(res *envoy_service_discovery_v3.DeltaDiscoveryResponse) {
	for _, resource := range res.GetResources() {
		s.clientResourceVersions[resource.GetName()] = resource.GetVersion()
	}
	for _, name := range res.GetRemovedResources() {
		delete(s.clientResourceVersions, name)
	}
}

// A Manager manages xDS resources.
type Manager struct {
	signal *signal.Signal
	health health.Provider

	mu        sync.Mutex
	resources map[string][]*envoy_service_discovery_v3.Resource

	// onResponsesQueued, if set, is called once a request or a resource
	// change has been handled, with the number of responses handed to the
	// sender, 0 included. Tests use it to know when the manager is done
	// reacting.
	onResponsesQueued func(n int)
}

// NewManager creates a new Manager.
func NewManager(resources map[string][]*envoy_service_discovery_v3.Resource) *Manager {
	return &Manager{
		signal: signal.New(),
		health: health.GetProviderManager(),

		resources: resources,
	}
}

// DeltaAggregatedResources implements the increment xDS server.
func (mgr *Manager) DeltaAggregatedResources(
	stream envoy_service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	ch := mgr.signal.Bind()
	defer mgr.signal.Unbind(ch)

	// stateByTypeURL and nonce belong to the goroutine that handles requests
	// and resource changes and queues the responses, so they need no lock.
	// mgr.mu only guards mgr.resources.
	stateByTypeURL := map[string]*streamState{}
	var nonce uint64

	// getDeltaResponse diffs the resources of a type against what was sent
	// to envoy.
	getDeltaResponse := func(typeURL string) *envoy_service_discovery_v3.DeltaDiscoveryResponse {
		state, ok := stateByTypeURL[typeURL]
		if !ok {
			return nil
		}

		mgr.mu.Lock()
		defer mgr.mu.Unlock()

		resources := mgr.resources[typeURL]
		res := &envoy_service_discovery_v3.DeltaDiscoveryResponse{
			TypeUrl: typeURL,
		}
		seen := make(map[string]struct{}, len(resources))
		for _, resource := range resources {
			if _, ok := state.unsubscribedResources[resource.Name]; ok {
				continue
			}
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
		state, ok := stateByTypeURL[req.GetTypeUrl()]
		if !ok {
			// first time we've seen a message for this type URL.
			state = &streamState{
				clientResourceVersions: req.GetInitialResourceVersions(),
				unsubscribedResources:  make(map[string]struct{}),
			}
			if state.clientResourceVersions == nil {
				state.clientResourceVersions = make(map[string]string)
			}
			stateByTypeURL[req.GetTypeUrl()] = state
		}

		check := getHealthCheck(req.GetTypeUrl())
		switch {
		case req.GetResponseNonce() == "":
			// neither an ACK or a NACK
		case req.GetErrorDetail() != nil:
			// a NACK
			logNACK(ctx, req)
			mgr.health.ReportError(check, errors.New(req.GetErrorDetail().GetMessage()))
		case req.GetResponseNonce() == state.lastNonce:
			// an ACK for the last response
			logACK(ctx, req)
			mgr.health.ReportStatus(check, health.StatusRunning)
		default:
			// an ACK for a response that's not the last response
			logEarlierACK(ctx, req, state.lastNonce)
		}

		// update subscriptions
		for _, name := range req.GetResourceNamesUnsubscribe() {
			state.unsubscribedResources[name] = struct{}{}
			delete(state.clientResourceVersions, name)
		}
		// from the docs:
		//   NOTE: the server must respond with all resources listed in
		//   resource_names_subscribe, even if it believes the client has
		//   the most recent version of them. The reason: the client may
		//   have dropped them, but then regained interest before it had
		//   a chance to send the unsubscribe message.
		// so the version sent is forgotten, unless the request states the
		// version the client holds, as the first request of a stream does
		for _, name := range req.GetResourceNamesSubscribe() {
			delete(state.unsubscribedResources, name)
			if _, ok := req.GetInitialResourceVersions()[name]; !ok {
				delete(state.clientResourceVersions, name)
			}
		}
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
				return context.Cause(ctx)
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
				return context.Cause(ctx)
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

			var responses []*envoy_service_discovery_v3.DeltaDiscoveryResponse
			for _, typeURL := range typeURLs {
				if res := getDeltaResponse(typeURL); res != nil {
					responses = append(responses, res)
				}
			}

			responses = buildDiscoveryResponsesForConsistentUpdates(responses)
			for _, res := range responses {
				// every response has its own nonce, so that an ACK identifies
				// the response it acknowledges
				nonce++
				res.Nonce = strconv.FormatUint(nonce, 10)
				state := stateByTypeURL[res.GetTypeUrl()]
				state.lastNonce = res.Nonce
				state.recordSent(res)

				select {
				case <-ctx.Done():
					return context.Cause(ctx)
				case outgoing <- res:
				}
			}
			if mgr.onResponsesQueued != nil {
				mgr.onResponsesQueued(len(responses))
			}
		}
	})
	// 3. send all outgoing messages
	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case res := <-outgoing:
				logSend(ctx, res)
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
	mgr.mu.Lock()
	mgr.resources = resources
	mgr.mu.Unlock()

	mgr.signal.Broadcast(ctx)
}

// buildDiscoveryResponsesForConsistentUpdates orders the responses of one
// change so that envoy applies it make before break. From the docs:
//
// In general, to avoid traffic drop, sequencing of updates should follow a make before break model, wherein:
//
// CDS updates (if any) must always be pushed first.
// EDS updates (if any) must arrive after CDS updates for the respective clusters.
// LDS updates must arrive after corresponding CDS/EDS updates.
// RDS updates related to the newly added listeners must arrive after CDS/EDS/LDS updates.
// VHDS updates (if any) related to the newly added RouteConfigurations must arrive after RDS updates.
// Stale CDS clusters and related EDS endpoints (ones no longer being referenced) can then be removed.
//
// Each type is sent whole, in that order, and only the removed clusters follow
// in a response of their own. Envoy applies the removals of a listener
// response before its additions, so a listener that replaces another on its
// address must travel with that removal, or envoy rejects it as a duplicate.
// Envoy ignores route configuration removals.
func buildDiscoveryResponsesForConsistentUpdates(in []*envoy_service_discovery_v3.DeltaDiscoveryResponse) (out []*envoy_service_discovery_v3.DeltaDiscoveryResponse) {
	var removedClusters *envoy_service_discovery_v3.DeltaDiscoveryResponse
	for _, r := range in {
		if r.TypeUrl == clusterTypeURL && len(r.RemovedResources) > 0 {
			removedClusters = &envoy_service_discovery_v3.DeltaDiscoveryResponse{
				TypeUrl:          r.TypeUrl,
				RemovedResources: r.RemovedResources,
			}
			if len(r.Resources) == 0 {
				continue
			}
			r = &envoy_service_discovery_v3.DeltaDiscoveryResponse{
				TypeUrl:   r.TypeUrl,
				Resources: r.Resources,
			}
		}
		out = append(out, r)
	}

	order := map[string]int{
		clusterTypeURL:            1,
		listenerTypeURL:           2,
		routeConfigurationTypeURL: 3,
	}
	slices.SortStableFunc(out, func(a, b *envoy_service_discovery_v3.DeltaDiscoveryResponse) int {
		return cmp.Compare(order[a.TypeUrl], order[b.TypeUrl])
	})

	if removedClusters != nil {
		out = append(out, removedClusters)
	}
	return out
}
