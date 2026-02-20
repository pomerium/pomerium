package health

import "fmt"

type Check string

const (
	// AuthenticationService checks if the authentication service is up and running
	AuthenticateService = Check("authenticate.service")
	// AuthorizationService checks if the authorization service is up and running
	AuthorizationService = Check("authorize.service")
	// EnvoyServer checks if the envoy server is up and running
	EnvoyServer = Check("envoy.server")
	// ProxyService checks if the proxy server is up and running
	ProxyService = Check("proxy.service")

	// BlobStore checks if the blob store is up and running
	BlobStore = Check("blob.store")

	// BuildDatabrokerConfig checks whether the Databroker config was applied
	DatabrokerBuildConfig = Check("config.databroker.build")
	// DatabrokerInitialSync checks whether the initial sync was successful
	DatabrokerInitialSync = Check("databroker.sync.initial")
	// DatabrokerCluster checks whether members of the databroker cluster are healthy
	DatabrokerCluster = Check("databroker.cluster")

	// StorageBackend checks whether the storage backend is healthy
	StorageBackend = Check("storage.backend")
	// StorageBackendCleanup checks the storage backend cleanup tasks are healthy
	StorageBackendCleanup = Check("storage.backend.cleanup")
	// StorageBackendNotification checks that the backend is processing notifications
	StorageBackendNotification = Check("storage.backend.notifications")
	// XDSCluster checks whether the XDS Cluster resources were applied
	XDSCluster = Check("xds.cluster")
	// XDSListener checks whether the XDS Listener resources were applied
	XDSListener = Check("xds.listener")
	// XDSRouteConfiguration checks whether the XDS RouteConfiguration resources were applied
	XDSRouteConfiguration = Check("xds.route-configuration")
	// XDSOther is a catch-all for other XDS resources
	XDSOther = Check("xds.other")
	// CollectAndSendTelemetry checks whether telemetry was collected and sent
	ZeroCollectAndSendTelemetry = Check("zero.telemetry.collect-and-send")
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
