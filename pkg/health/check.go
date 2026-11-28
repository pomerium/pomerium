package health

import "fmt"

type Check string

const (
	// AuthenticationService checks if the authentication service is up and running
	AuthenticateService = Check("authenticate.service")
	// AuthorizationService checks if the authorization service is up and running
	AuthorizationService = Check("authorize.service")
	// BlobStorage checks if the blob store is valid and healthy
	BlobStorage = Check("storage.blob")
	// BuildDatabrokerConfig checks whether the Databroker config was applied
	DatabrokerBuildConfig = Check("config.databroker.build")
	// DatabrokerCluster checks whether members of the databroker cluster are healthy
	DatabrokerCluster = Check("databroker.cluster")
	// DatabrokerInitialSync checks whether the initial sync was successful
	DatabrokerInitialSync = Check("databroker.sync.initial")
	// EnvoyDynamicExtensions checks that the set of expected extensions configured
	// are actually successfully initialized in envoy
	EnvoyDynamicExtensions = Check("envoy.extensions")
	// EnvoyServer checks if the envoy server is up and running
	EnvoyServer = Check("envoy.server")
	// EnvoyOverloaded checks whether envoy is still accepting connections
	// w.r. to its configured overload actions.
	EnvoyOverloaded = Check("envoy.overloaded")

	// ProxyService checks if the proxy server is up and running
	ProxyService = Check("proxy.service")
	// RecordingHandler is ready to receive upload traffic from envoy for session recordings
	RecordingHandler = Check("recording.handler")
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
	// XDSOther is a catch-all for other XDS resources
	XDSOther = Check("xds.other")
	// XDSRouteConfiguration checks whether the XDS RouteConfiguration resources were applied
	XDSRouteConfiguration = Check("xds.route-configuration")
	// ZeroBootstrapConfigSave checks whether the Zero bootstrap config was saved
	ZeroBootstrapConfigSave = Check("zero.bootstrap-config.save")
	// CollectAndSendTelemetry checks whether telemetry was collected and sent
	ZeroCollectAndSendTelemetry = Check("zero.telemetry.collect-and-send")
	// ZeroConnect checks whether the Zero Connect service is connected
	ZeroConnect = Check("zero.connect")
	// RoutesReachable checks whether all referenced routes can be resolved to this instance
	ZeroRoutesReachable = Check("routes.reachable")
)

// ZeroResourceBundle checks whether the Zero resource bundle was applied
func ZeroResourceBundle(bundleID string) Check {
	return Check(fmt.Sprintf("zero.resource-bundle.%s", bundleID))
}

// IdentityProvider checks whether the JWT identity provider named `name` (a key
// of the identity_providers configuration map) could be built. An erroring
// provider rejects the bearer tokens of its own issuer; the other providers in
// the map are unaffected.
func IdentityProvider(name string) Check {
	return Check(fmt.Sprintf("identity-provider.%s", name))
}
