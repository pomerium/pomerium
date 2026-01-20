package tunnel

import (
	"context"
	"maps"

	tea "charm.land/bubbletea/v2"

	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type Program struct {
	*tea.Program
	portForwardEndpoints map[string]portforward.RoutePortForwardInfo
}

func NewProgram(ctx context.Context, model *Model, opts ...tea.ProgramOption) *Program {
	return &Program{
		Program: tea.NewProgram(model, append(opts,
			tea.WithContext(ctx),
			tea.WithoutSignalHandler(),
		)...),
		portForwardEndpoints: map[string]portforward.RoutePortForwardInfo{},
	}
}

// OnClusterEndpointsUpdated implements portforward.UpdateListener.
func (ts *Program) OnClusterEndpointsUpdated(added map[string]portforward.RoutePortForwardInfo, removed map[string]struct{}) {
	maps.Copy(ts.portForwardEndpoints, added)
	for k := range removed {
		delete(ts.portForwardEndpoints, k)
	}
	go ts.Send(maps.Clone(ts.portForwardEndpoints))
}

// OnPermissionsUpdated implements portforward.UpdateListener.
func (ts *Program) OnPermissionsUpdated(permissions []portforward.Permission) {
	go ts.Send(permissions)
}

// OnRoutesUpdated implements portforward.UpdateListener.
func (ts *Program) OnRoutesUpdated(routes []portforward.RouteInfo) {
	go ts.Send(routes)
}
