package models

import (
	"fmt"
	"strings"

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

type Route portforward.RouteInfo

func (r Route) Key() string {
	return r.ClusterID
}

type RouteUpdateMsg = IndexUpdateMsg[Route, string]

type RouteModel struct {
	ItemModel[Route, string]
	activePortForwards    map[string]portforward.RoutePortForwardInfo
	clusterHealth         map[string]string
	clusterEndpointStatus map[string]string
	eventHandlers         RouteModelEventHandlers
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

func (m *RouteModel) BuildRow(route Route) []string {
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

	to, _, _ := route.To.Flatten()
	remote := fmt.Sprintf("%s:%d", route.From, route.Port)
	local := strings.Join(to, ",")
	return []string{status, health, remote, local}
}

func (m *RouteModel) HandleClusterEndpointsUpdate(added map[string]portforward.RoutePortForwardInfo, removed map[string]struct{}) {
	for k, v := range added {
		m.activePortForwards[k] = v
		m.Put(Route(v.RouteInfo))
	}
	for k := range removed {
		delete(m.activePortForwards, k)
		m.Delete(m.Index(k))
	}
}

func (m *RouteModel) HandleRoutesUpdate(routes []portforward.RouteInfo) {
	items := make([]Route, len(routes))
	for i, r := range routes {
		items[i] = Route(r)
	}
	m.Reset(items)
}

func (m *RouteModel) HandleClusterHealthUpdate(msg *datav3.HealthCheckEvent) {
	var md extensions_ssh.EndpointMetadata
	err := msg.Metadata.TypedFilterMetadata["com.pomerium.ssh.endpoint"].UnmarshalTo(&md)
	if err != nil {
		panic(err)
	}
	affected := Route(m.activePortForwards[msg.ClusterName].RouteInfo)
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
	m.Put(affected)
}

func (m *RouteModel) EditRoute(route Route) {
	m.eventHandlers.OnRouteEditRequest(route)
}
