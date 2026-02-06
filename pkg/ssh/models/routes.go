package models

import (
	"fmt"
	"strings"
	"sync"

	datav3 "github.com/envoyproxy/go-control-plane/envoy/data/core/v3"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

const (
	HealthHealthy   = "HEALTHY"
	HealthDegraded  = "DEGRADED"
	HealthUnhealthy = "UNHEALTHY"
	HealthUnknown   = "UNKNOWN"
)

const (
	EndpointStatusActive   = "ACTIVE"
	EndpointStatusInactive = "INACTIVE"
	EndpointStatusUnknown  = "UNKNOWN"
)

type Route struct {
	portforward.RouteInfo
	Status string
	Health string
}

func (r Route) Key() string {
	return r.ClusterID
}

func (r Route) ToRow() []string {
	to, _, _ := r.To.Flatten()
	remote := fmt.Sprintf("%s:%d", r.From, r.Port)
	local := strings.Join(to, ",")
	return []string{r.Status, r.Health, remote, local}
}

type RouteModel struct {
	ItemModel[Route, string]
	activePortForwards    map[string]portforward.RoutePortForwardInfo
	clusterHealth         map[string]string
	clusterEndpointStatus map[string]string
	eventHandlers         RouteModelEventHandlers
	mu                    sync.Mutex
}

type RouteModelEventHandlers struct {
	OnRouteEditRequest func(route Route)
}

type EventHandlers struct {
	RouteDataModelEventHandlers RouteModelEventHandlers
}

func NewRouteModel(eventHandlers RouteModelEventHandlers) *RouteModel {
	return &RouteModel{
		ItemModel:             NewItemModel[Route](),
		activePortForwards:    map[string]portforward.RoutePortForwardInfo{},
		clusterHealth:         map[string]string{},
		clusterEndpointStatus: map[string]string{},
		eventHandlers:         eventHandlers,
	}
}

func (m *RouteModel) HandleClusterEndpointsUpdate(added map[string]portforward.RoutePortForwardInfo, removed map[string]struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range added {
		m.activePortForwards[k] = v
		route := Route{RouteInfo: v.RouteInfo}
		m.hydrateHealthStatus(&route)
		m.Put(route)
	}
	for k := range removed {
		delete(m.activePortForwards, k)
		if idx := m.Index(k); idx.IsValid(m) {
			m.Delete(idx)
		}
	}
}

func (m *RouteModel) HandleRoutesUpdate(routes []portforward.RouteInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]Route, len(routes))
	for i, r := range routes {
		route := Route{RouteInfo: r}
		m.hydrateHealthStatus(&route)
		items[i] = route
	}
	m.Reset(items)
}

func (m *RouteModel) HandleClusterHealthUpdate(msg *datav3.HealthCheckEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var md extensions_ssh.EndpointMetadata
	err := msg.Metadata.TypedFilterMetadata["com.pomerium.ssh.endpoint"].UnmarshalTo(&md)
	if err != nil {
		panic(err)
	}
	affected := Route{RouteInfo: m.activePortForwards[msg.ClusterName].RouteInfo}
	switch event := msg.Event.(type) {
	case *datav3.HealthCheckEvent_AddHealthyEvent:
		m.clusterHealth[msg.ClusterName] = HealthHealthy
		m.clusterEndpointStatus[msg.ClusterName] = EndpointStatusActive
	case *datav3.HealthCheckEvent_EjectUnhealthyEvent:
		m.clusterHealth[msg.ClusterName] = HealthUnhealthy
		m.clusterEndpointStatus[msg.ClusterName] = EndpointStatusInactive
	case *datav3.HealthCheckEvent_DegradedHealthyHost:
		m.clusterHealth[msg.ClusterName] = HealthDegraded
	case *datav3.HealthCheckEvent_HealthCheckFailureEvent:
		m.clusterHealth[msg.ClusterName] = HealthUnhealthy
	case *datav3.HealthCheckEvent_NoLongerDegradedHost:
		m.clusterHealth[msg.ClusterName] = HealthHealthy
	case *datav3.HealthCheckEvent_SuccessfulHealthCheckEvent:
		m.clusterHealth[msg.ClusterName] = HealthHealthy
	default:
		panic(fmt.Sprintf("unexpected corev3.isHealthCheckEvent_Event: %#v", event))
	}
	m.hydrateHealthStatus(&affected)
	m.Put(affected)
}

func (m *RouteModel) hydrateHealthStatus(route *Route) {
	status := "--"
	health := "--"
	if _, ok := m.activePortForwards[route.ClusterID]; ok {
		status = EndpointStatusActive
		if stat, ok := m.clusterEndpointStatus[route.ClusterID]; ok {
			status = stat
		}
		health = m.clusterHealth[route.ClusterID]
		if health == "" {
			health = HealthUnknown
		}
	}
	route.Status = status
	route.Health = health
}

func (m *RouteModel) EditRoute(route Route) {
	m.eventHandlers.OnRouteEditRequest(route)
}
