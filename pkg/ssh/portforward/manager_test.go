package portforward_test

import (
	"bytes"
	"cmp"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
	mock_portforward "github.com/pomerium/pomerium/pkg/ssh/portforward/mock"
)

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}

func TestPortForwardManager(t *testing.T) {
	routes := []config.Policy{
		{
			From:           "https://route-1",
			To:             mustParseWeightedURLs(t, "http://dst1"),
			UpstreamTunnel: &config.UpstreamTunnel{},
		},
		{
			From:           "https://route-2",
			To:             mustParseWeightedURLs(t, "http://dst2"),
			UpstreamTunnel: &config.UpstreamTunnel{},
		},
		{
			From:           "https://ignore",
			To:             mustParseWeightedURLs(t, "http://ignore"),
			UpstreamTunnel: nil,
		},
		{
			From:           "https:/invalidurl",
			To:             mustParseWeightedURLs(t, "http://ignore"),
			UpstreamTunnel: &config.UpstreamTunnel{},
		},
		{
			From:           "ssh://route-3",
			To:             mustParseWeightedURLs(t, "ssh://dst3:22"),
			UpstreamTunnel: &config.UpstreamTunnel{},
		},
		{
			From:           "unknown://ignore",
			To:             mustParseWeightedURLs(t, "http://ignore"),
			UpstreamTunnel: &config.UpstreamTunnel{},
		},
	}

	t.Run("Static", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cfg := &config.Config{Options: config.NewDefaultOptions()}
		cfg.Options.Addr = "localhost:8080"
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Routes = routes

		route1, route2, route3 := &cfg.Options.Routes[0], &cfg.Options.Routes[1], &cfg.Options.Routes[4]

		expectedInfo1 := portforward.RouteInfo{
			Hostname:  "route-1",
			Port:      443,
			ClusterID: envoyconfig.GetClusterID(route1),
		}

		expectedInfo2 := portforward.RouteInfo{
			Hostname:  "route-2",
			Port:      443,
			ClusterID: envoyconfig.GetClusterID(route2),
		}

		expectedInfo3 := portforward.RouteInfo{
			Hostname:  "route-3",
			Port:      22,
			ClusterID: envoyconfig.GetClusterID(route3),
		}

		listener := mock_portforward.NewMockUpdateListener(ctrl)
		listener.EXPECT().OnRoutesUpdated(gomock.Len(3))

		mgr := portforward.NewManager()
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})
		mgr.UpdateAuthorizedRoutes([]portforward.RouteInfo{expectedInfo1, expectedInfo2, expectedInfo3})

		listener.EXPECT().OnPermissionsUpdated(gomock.Len(0))
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(0))
		// Add the update listener
		mgr.AddUpdateListener(listener)

		{
			listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(1), gomock.Len(0))
			listener.EXPECT().OnPermissionsUpdated(gomock.Len(1))
			serverPort, err := mgr.AddPermission("route-1", 443)
			assert.NoError(t, err)
			assert.False(t, serverPort.IsDynamic)
			assert.Equal(t, uint32(443), serverPort.Value)
		}

		{
			listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(1), gomock.Len(0))
			listener.EXPECT().OnPermissionsUpdated(gomock.Len(2))
			serverPort, err := mgr.AddPermission("route-2", 443)
			assert.NoError(t, err)
			assert.False(t, serverPort.IsDynamic)
			assert.Equal(t, uint32(443), serverPort.Value)
		}

		// Add a second update listener
		listener2 := mock_portforward.NewMockUpdateListener(ctrl)
		listener2.EXPECT().OnRoutesUpdated(gomock.Len(3))
		listener2.EXPECT().OnPermissionsUpdated(gomock.Len(2))
		listener2.EXPECT().OnClusterEndpointsUpdated(gomock.Len(2), gomock.Len(0))
		mgr.AddUpdateListener(listener2)

		// Remove the first one
		mgr.RemoveUpdateListener(listener)

		// Only listener2 should get updates now
		{
			listener2.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(1))
			listener2.EXPECT().OnPermissionsUpdated(gomock.Len(1))
			assert.ErrorContains(t, mgr.RemovePermission("route-2", 442), "port-forward not found")
			assert.ErrorContains(t, mgr.RemovePermission("route-2", 22), "port-forward not found")
			err := mgr.RemovePermission("route-2", 443)
			assert.NoError(t, err)
			assert.ErrorContains(t, mgr.RemovePermission("route-2", 443), "port-forward not found")
		}
		{
			listener2.EXPECT().OnClusterEndpointsUpdated(gomock.Len(1), gomock.Len(0))
			listener2.EXPECT().OnPermissionsUpdated(gomock.Len(2))
			serverPort, err := mgr.AddPermission("route-3", 22)
			assert.NoError(t, err)
			assert.False(t, serverPort.IsDynamic)
			assert.Equal(t, uint32(22), serverPort.Value)
		}
	})
	t.Run("Dynamic", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cfg := &config.Config{Options: config.NewDefaultOptions()}
		cfg.Options.Routes = routes
		cfg.Options.SSHAddr = "localhost:22"
		route1, route2, route3 := &cfg.Options.Routes[0], &cfg.Options.Routes[1], &cfg.Options.Routes[4]
		expectedInfo1 := portforward.RouteInfo{
			Hostname:  "route-1",
			Port:      443,
			ClusterID: envoyconfig.GetClusterID(route1),
		}

		expectedInfo2 := portforward.RouteInfo{
			Hostname:  "route-2",
			Port:      443,
			ClusterID: envoyconfig.GetClusterID(route2),
		}

		expectedInfo3 := portforward.RouteInfo{
			Hostname:  "route-3",
			Port:      22,
			ClusterID: envoyconfig.GetClusterID(route3),
		}

		listener := mock_portforward.NewMockUpdateListener(ctrl)

		mgr := portforward.NewManager()
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})
		mgr.UpdateAuthorizedRoutes([]portforward.RouteInfo{expectedInfo1, expectedInfo2, expectedInfo3})

		listener.EXPECT().OnRoutesUpdated(gomock.Len(3))
		listener.EXPECT().OnPermissionsUpdated(gomock.Len(0))
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(0))
		mgr.AddUpdateListener(listener)

		var entries []portforward.Permission
		var added []portforward.RoutePortForwardInfo
		permissionUpdate := listener.EXPECT().
			OnPermissionsUpdated(gomock.Len(1)).
			Do(func(ps []portforward.Permission) {
				entries = ps
			})
		listener.EXPECT().
			OnClusterEndpointsUpdated(gomock.Len(3), gomock.Len(0)).
			Do(func(m1 map[string]portforward.RoutePortForwardInfo, _ map[string]struct{}) {
				added = slices.Collect(maps.Values(m1))
			}).
			After(permissionUpdate.Call)

		serverPort, err := mgr.AddPermission("route-*", 0)
		require.NoError(t, err)
		require.True(t, serverPort.IsDynamic)
		require.GreaterOrEqual(t, serverPort.Value, uint32(32768))
		require.Len(t, entries, 1)
		require.Len(t, added, 3)
		slices.SortFunc(added, func(a, b portforward.RoutePortForwardInfo) int {
			return cmp.Compare(a.Hostname, b.Hostname)
		})

		assert.Equal(t, entries[0], added[0].Permission)
		assert.Equal(t, "route-1", added[0].Hostname)
		assert.Equal(t, uint32(443), added[0].Port)
		assert.Equal(t, envoyconfig.GetClusterID(route1), added[0].ClusterID)

		assert.Equal(t, entries[0], added[1].Permission)
		assert.Equal(t, "route-2", added[1].Hostname)
		assert.Equal(t, uint32(443), added[1].Port)
		assert.Equal(t, envoyconfig.GetClusterID(route2), added[1].ClusterID)

		assert.Equal(t, entries[0], added[2].Permission)
		assert.Equal(t, "route-3", added[2].Hostname)
		assert.Equal(t, uint32(22), added[2].Port)
		assert.Equal(t, envoyconfig.GetClusterID(route3), added[2].ClusterID)

		{
			listener.EXPECT().
				OnPermissionsUpdated(gomock.Len(0))
			listener.EXPECT().
				OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(3))
			mgr.RemovePermission("route-*", serverPort.Value)

			assert.ErrorContains(t, mgr.RemovePermission("route-*", serverPort.Value), "port-forward not found")
		}
	})

	t.Run("DynamicWithPermissionFiltering", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cfg := &config.Config{Options: config.NewDefaultOptions()}
		cfg.Options.Routes = routes
		cfg.Options.SSHAddr = "localhost:22"
		route1, route2 := &cfg.Options.Routes[0], &cfg.Options.Routes[1]

		expectedInfo1 := portforward.RouteInfo{
			Hostname:  "route-1",
			Port:      443,
			ClusterID: envoyconfig.GetClusterID(route1),
		}

		expectedInfo2 := portforward.RouteInfo{
			Hostname:  "route-2",
			Port:      443,
			ClusterID: envoyconfig.GetClusterID(route2),
		}

		listener := mock_portforward.NewMockUpdateListener(ctrl)

		mgr := portforward.NewManager()
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})
		mgr.UpdateAuthorizedRoutes([]portforward.RouteInfo{expectedInfo1, expectedInfo2})

		listener.EXPECT().OnRoutesUpdated(gomock.Len(2))
		listener.EXPECT().OnPermissionsUpdated(gomock.Len(0))
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(0))
		mgr.AddUpdateListener(listener)

		var entries []portforward.Permission
		var added []portforward.RoutePortForwardInfo
		permissionUpdate := listener.EXPECT().
			OnPermissionsUpdated(gomock.Len(1)).
			Do(func(ps []portforward.Permission) {
				entries = ps
			})
		listener.EXPECT().
			OnClusterEndpointsUpdated(gomock.Len(2), gomock.Len(0)).
			Do(func(m1 map[string]portforward.RoutePortForwardInfo, _ map[string]struct{}) {
				added = slices.Collect(maps.Values(m1))
			}).
			After(permissionUpdate.Call)

		mgr.AddPermission("route-*", 0)
		require.Len(t, entries, 1)
		require.Len(t, added, 2)
		slices.SortFunc(added, func(a, b portforward.RoutePortForwardInfo) int {
			return cmp.Compare(a.Hostname, b.Hostname)
		})

		assert.Equal(t, entries[0], added[0].Permission)
		assert.Equal(t, "route-1", added[0].Hostname)
		assert.Equal(t, uint32(443), added[0].Port)
		assert.Equal(t, envoyconfig.GetClusterID(route1), added[0].ClusterID)

		assert.Equal(t, entries[0], added[1].Permission)
		assert.Equal(t, "route-2", added[1].Hostname)
		assert.Equal(t, uint32(443), added[1].Port)
		assert.Equal(t, envoyconfig.GetClusterID(route2), added[1].ClusterID)
	})

	t.Run("DuplicateRequest", func(t *testing.T) {
		cfg := &config.Config{Options: config.NewDefaultOptions()}
		cfg.Options.Routes = routes
		cfg.Options.SSHAddr = "localhost:22"

		mgr := portforward.NewManager()
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})

		_, err := mgr.AddPermission("route-1", 443)
		assert.NoError(t, err)
		_, err = mgr.AddPermission("route-1", 443)
		assert.ErrorContains(t, err, "received duplicate port forward request (host: route-1, port: 443)")
	})

	t.Run("AddPermissionsBeforePortsEnabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		listener := mock_portforward.NewMockUpdateListener(ctrl)
		mgr := portforward.NewManager()
		listener.EXPECT().OnRoutesUpdated(gomock.Len(0))
		listener.EXPECT().OnPermissionsUpdated(gomock.Len(0))
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(0))
		mgr.AddUpdateListener(listener)

		listener.EXPECT().OnRoutesUpdated(gomock.Len(2))
		mgr.UpdateAuthorizedRoutes([]portforward.RouteInfo{
			{
				Hostname:  "route-1",
				Port:      443,
				ClusterID: "1",
			},
			{
				Hostname:  "route-2",
				Port:      22,
				ClusterID: "2",
			},
		})

		listener.EXPECT().OnPermissionsUpdated(gomock.Len(1))
		_, err := mgr.AddPermission("route-1", 443)
		assert.NoError(t, err)

		listener.EXPECT().OnPermissionsUpdated(gomock.Len(2))
		_, err = mgr.AddPermission("route-2", 22)
		assert.NoError(t, err)

		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(2), gomock.Len(0))
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(2))
		mgr.UpdateEnabledStaticPorts([]uint{})
	})

	t.Run("TooManyPermissions", func(t *testing.T) {
		cfg := &config.Config{Options: config.NewDefaultOptions()}
		hostname := bytes.Repeat([]byte{'a'}, portforward.MaxPermissionEntries)
		cfg.Options.Routes = append(cfg.Options.Routes, config.Policy{
			From:           "https://" + string(hostname),
			To:             mustParseWeightedURLs(t, "http://dst1"),
			UpstreamTunnel: &config.UpstreamTunnel{},
		})

		mgr := portforward.NewManager()
		mgr.UpdateEnabledStaticPorts([]uint{443})

		for i := range portforward.MaxPermissionEntries {
			h := slices.Clone(hostname)
			h[i] = '?'
			_, err := mgr.AddPermission(string(h), 443)
			assert.NoError(t, err)
		}
		_, err := mgr.AddPermission("*", 0)
		assert.ErrorContains(t, err, "exceeded maximum allowed port-forward requests")
	})

	t.Run("AddListenerBeforeUpdatingRoutes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cfg := &config.Config{Options: config.NewDefaultOptions()}
		cfg.Options.Routes = routes
		cfg.Options.SSHAddr = "localhost:22"

		listener := mock_portforward.NewMockUpdateListener(ctrl)
		mgr := portforward.NewManager()

		listener.EXPECT().OnRoutesUpdated(gomock.Len(0))
		listener.EXPECT().OnPermissionsUpdated(gomock.Len(0))
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(0))
		mgr.AddUpdateListener(listener)

		listener.EXPECT().OnRoutesUpdated(gomock.Len(1))
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})
		mgr.UpdateAuthorizedRoutes([]portforward.RouteInfo{
			{
				Hostname:  "route-1",
				Port:      443,
				ClusterID: envoyconfig.GetClusterID(&cfg.Options.Routes[0]),
			},
		})
	})

	t.Run("EnableDisableListener", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		cfg := &config.Config{Options: config.NewDefaultOptions()}
		cfg.Options.Addr = "localhost:8080"
		cfg.Options.SSHAddr = "localhost:2200"
		cfg.Options.Routes = routes
		route1, route2, route3 := &cfg.Options.Routes[0], &cfg.Options.Routes[1], &cfg.Options.Routes[4]
		expectedInfo1 := portforward.RouteInfo{
			Hostname:  "route-1",
			Port:      443,
			ClusterID: envoyconfig.GetClusterID(route1),
		}

		expectedInfo2 := portforward.RouteInfo{
			Hostname:  "route-2",
			Port:      443,
			ClusterID: envoyconfig.GetClusterID(route2),
		}

		expectedInfo3 := portforward.RouteInfo{
			Hostname:  "route-3",
			Port:      22,
			ClusterID: envoyconfig.GetClusterID(route3),
		}

		listener := mock_portforward.NewMockUpdateListener(ctrl)
		mgr := portforward.NewManager()
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})
		mgr.UpdateAuthorizedRoutes([]portforward.RouteInfo{expectedInfo1, expectedInfo2, expectedInfo3})

		listener.EXPECT().OnRoutesUpdated(gomock.Len(3))
		listener.EXPECT().OnPermissionsUpdated(gomock.Len(0))
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(0))
		mgr.AddUpdateListener(listener)

		listener.EXPECT().OnPermissionsUpdated(gomock.Len(1))
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(1), gomock.Len(0))
		_, err := mgr.AddPermission("route-3", 22)
		require.NoError(t, err)

		// Update the config to disable the ssh listener. This should remove the
		// cluster endpoint for the ssh route
		cfg.Options.SSHAddr = ""
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(1))
		mgr.UpdateEnabledStaticPorts([]uint{443})

		// Re-enable the ssh listener. This should restore the route from the
		// existing ssh permission
		cfg.Options.SSHAddr = "localhost:2200"
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(1), gomock.Len(0))
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})

		// Do the same thing again, but delete the ssh permission while it is
		// disabled; it should not be re-enabled when the address is added back

		cfg.Options.SSHAddr = ""
		listener.EXPECT().OnClusterEndpointsUpdated(gomock.Len(0), gomock.Len(1))
		mgr.UpdateEnabledStaticPorts([]uint{443})

		listener.EXPECT().OnPermissionsUpdated(gomock.Len(0))
		require.NoError(t, mgr.RemovePermission("route-3", 22))

		cfg.Options.SSHAddr = "localhost:2200"
		mgr.UpdateEnabledStaticPorts([]uint{443, 22})

		// Order should not matter when updating the enabled ports. Expect no
		// callbacks here
		mgr.UpdateEnabledStaticPorts([]uint{22, 443})
	})
}
