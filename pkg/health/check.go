package health

import "fmt"

type Check string

const (
	// StorageBackend checks whether the storage backend is healthy
	StorageBackend = Check("storage.backend")
	// XDSCluster checks whether the XDS Cluster resources were applied
	XDSCluster = Check("xds.cluster")
	// XDSListener checks whether the XDS Listener resources were applied
	XDSListener = Check("xds.listener")
	// XDSRouteConfiguration checks whether the XDS RouteConfiguration resources were applied
	XDSRouteConfiguration = Check("xds.route-configuration")
	// XDSOther is a catch-all for other XDS resources
	XDSOther = Check("xds.other")
	// ZeroBootstrapConfigSave checks whether the Zero bootstrap config was saved
	ZeroBootstrapConfigSave = Check("zero.bootstrap-config.save")
	// ZeroConnect checks whether the Zero Connect service is connected
	ZeroConnect = Check("zero.connect")
	// RoutesReachable checks whether all referenced routes can be resolved to this instance
	RoutesReachable = Check("routes.reachable")
)

// ZeroResourceBundle checks whether the Zero resource bundle was applied
func ZeroResourceBundle(bundleID string) Check {
	return Check(fmt.Sprintf("zero.resource-bundle.%s", bundleID))
}
