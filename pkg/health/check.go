package health

import "fmt"

type Check string

const (
	// BuildDatabrokerConfig checks whether the Databroker config was applied
	BuildDatabrokerConfig = Check("config.databroker.build")
	// CollectAndSendTelemetry checks whether telemetry was collected and sent
	CollectAndSendTelemetry = Check("zero.telemetry.collect-and-send")
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
	ZeroRoutesReachable = Check("routes.reachable")
)

// ZeroResourceBundle checks whether the Zero resource bundle was applied
func ZeroResourceBundle(bundleID string) Check {
	return Check(fmt.Sprintf("zero.resource-bundle.%s", bundleID))
}
