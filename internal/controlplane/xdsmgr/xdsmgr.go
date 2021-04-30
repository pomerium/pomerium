// Package xdsmgr implements a resource discovery manager for envoy.
package xdsmgr

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/contextkeys"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

const (
	maxNonceCacheSize = 1 << 12
)

type streamState struct {
	typeURL                string
	clientResourceVersions map[string]string
	unsubscribedResources  map[string]struct{}
}

var onHandleDeltaRequest = func(state *streamState) {}

// A Manager manages xDS resources.
type Manager struct {
	signal       *signal.Signal
	eventHandler func(*configpb.EnvoyConfigurationEvent)

	mu        sync.Mutex
	nonce     string
	resources map[string][]*envoy_service_discovery_v3.Resource

	nonceToConfig *lru.Cache
}

// NewManager creates a new Manager.
func NewManager(resources map[string][]*envoy_service_discovery_v3.Resource, eventHandler func(*configpb.EnvoyConfigurationEvent)) *Manager {
	nonceToConfig, _ := lru.New(maxNonceCacheSize) // the only error they return is when size is negative, which never happens

	return &Manager{
		signal:       signal.New(),
		eventHandler: eventHandler,

		nonceToConfig: nonceToConfig,
		nonce:         uuid.NewString(),
		resources:     resources,
	}
}

// DeltaAggregatedResources implements the increment xDS server.
func (mgr *Manager) DeltaAggregatedResources(
	stream envoy_service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	ch := mgr.signal.Bind()
	defer mgr.signal.Unbind(ch)

	stateByTypeURL := map[string]*streamState{}

	getDeltaResponse := func(ctx context.Context, typeURL string) *envoy_service_discovery_v3.DeltaDiscoveryResponse {
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

			mgr.nackEvent(ctx, req)
		case req.GetResponseNonce() == mgr.nonce:
			// an ACK for the last response
			// - set the client resource versions to the current resource versions
			state.clientResourceVersions = make(map[string]string)
			for _, resource := range mgr.resources[req.GetTypeUrl()] {
				state.clientResourceVersions[resource.Name] = resource.Version
			}

			mgr.ackEvent(ctx, req)
		default:
			// an ACK for a response that's not the last response
			mgr.ackEvent(ctx, req)
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
					mgr.changeEvent(ctx, res)
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
func (mgr *Manager) Update(ctx context.Context, resources map[string][]*envoy_service_discovery_v3.Resource) {
	nonce := uuid.New().String()

	mgr.mu.Lock()
	mgr.nonce = nonce
	mgr.resources = resources
	mgr.nonceToConfig.Add(nonce, ctx.Value(contextkeys.DatabrokerConfigVersion))
	mgr.mu.Unlock()

	mgr.signal.Broadcast(ctx)
}

func (mgr *Manager) nonceToConfigVersion(nonce string) (ver uint64) {
	val, ok := mgr.nonceToConfig.Get(nonce)
	if !ok {
		return 0
	}
	ver, _ = val.(uint64)
	return ver
}

func (mgr *Manager) nackEvent(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
	mgr.eventHandler(&configpb.EnvoyConfigurationEvent{
		Kind:                 configpb.EnvoyConfigurationEvent_EVENT_DISCOVERY_REQUEST,
		Time:                 timestamppb.Now(),
		Message:              req.ErrorDetail.Message,
		Code:                 req.ErrorDetail.Code,
		Details:              req.ErrorDetail.Details,
		ResourceSubscribed:   req.ResourceNamesSubscribe,
		ResourceUnsubscribed: req.ResourceNamesUnsubscribe,
		ConfigVersion:        mgr.nonceToConfigVersion(req.ResponseNonce),
	})

	bs, _ := json.Marshal(req.ErrorDetail.Details)
	log.Error(ctx).
		Err(errors.New(req.ErrorDetail.Message)).
		Str("resource_type", req.TypeUrl).
		Strs("resources_unsubscribe", req.ResourceNamesUnsubscribe).
		Strs("resources_subscribe", req.ResourceNamesSubscribe).
		Uint64("nonce_version", mgr.nonceToConfigVersion(req.ResponseNonce)).
		Int32("code", req.ErrorDetail.Code).
		RawJSON("details", bs).Msg("error applying configuration")
}

func (mgr *Manager) ackEvent(ctx context.Context, req *envoy_service_discovery_v3.DeltaDiscoveryRequest) {
	mgr.eventHandler(&configpb.EnvoyConfigurationEvent{
		Kind:                 configpb.EnvoyConfigurationEvent_EVENT_DISCOVERY_REQUEST,
		Time:                 timestamppb.Now(),
		ConfigVersion:        mgr.nonceToConfigVersion(req.ResponseNonce),
		ResourceSubscribed:   req.ResourceNamesSubscribe,
		ResourceUnsubscribed: req.ResourceNamesUnsubscribe,
		Message:              "ok",
	})

	log.Debug(ctx).
		Str("resource_type", req.TypeUrl).
		Strs("resources_unsubscribe", req.ResourceNamesUnsubscribe).
		Strs("resources_subscribe", req.ResourceNamesSubscribe).
		Uint64("nonce_version", mgr.nonceToConfigVersion(req.ResponseNonce)).
		Msg("ACK")
}

func (mgr *Manager) changeEvent(ctx context.Context, res *envoy_service_discovery_v3.DeltaDiscoveryResponse) {
	mgr.eventHandler(&configpb.EnvoyConfigurationEvent{
		Kind:                 configpb.EnvoyConfigurationEvent_EVENT_DISCOVERY_RESPONSE,
		Time:                 timestamppb.Now(),
		ConfigVersion:        mgr.nonceToConfigVersion(res.Nonce),
		ResourceSubscribed:   resourceNames(res.Resources),
		ResourceUnsubscribed: res.RemovedResources,
		Message:              "change",
	})
	log.Debug(ctx).
		Uint64("ctx_config_version", mgr.nonceToConfigVersion(res.Nonce)).
		Str("nonce", res.Nonce).
		Str("type", res.TypeUrl).
		Strs("subscribe", resourceNames(res.Resources)).
		Strs("removed", res.RemovedResources).
		Msg("sent update")
}

func resourceNames(res []*envoy_service_discovery_v3.Resource) []string {
	txt := make([]string, 0, len(res))
	for _, r := range res {
		txt = append(txt, r.Name)
	}
	return txt
}
