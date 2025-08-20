package health

import (
	"fmt"
	"sync"

	"github.com/samber/lo"
)

var (
	defaultCheckMu = &sync.RWMutex{}
	defaultChecks  = map[Check]struct{}{}
)

type Check string

// ModifyExpected deregisters the delete checks, then
// registers the add checks. It is meant to be an atomic update operation.
func ModifyExpected(toDelete []Check, toAdd []Check) {
	defaultCheckMu.Lock()
	defer defaultCheckMu.Unlock()
	for _, del := range toDelete {
		delete(defaultChecks, del)
	}
	for _, check := range toAdd {
		defaultChecks[check] = struct{}{}
	}
}

func RegisterExpected(checks ...Check) {
	defaultCheckMu.Lock()
	defer defaultCheckMu.Unlock()
	for _, check := range checks {
		defaultChecks[check] = struct{}{}
	}
}

func DeregisterExpected(checks ...Check) {
	defaultCheckMu.Lock()
	defer defaultCheckMu.Unlock()
	for _, check := range checks {
		delete(defaultChecks, check)
	}
}

func SetDefaultExpected(
	checks ...Check,
) {
	defaultCheckMu.Lock()
	defer defaultCheckMu.Unlock()
	defaultChecks = lo.Associate(checks, func(check Check) (Check, struct{}) {
		return check, struct{}{}
	})
}

func getDefaultExpected() map[Check]struct{} {
	defaultCheckMu.RLock()
	defer defaultCheckMu.RUnlock()
	return defaultChecks
}

// func init() {
// 	SetDefaultExpected(
// 		DatabrokerBuildConfig,
// 		DatabrokerInitialSync,
// 		// CollectAndSendTelemetry,
// 		StorageBackend,
// 		XDSCluster,
// 		XDSListener,
// 		XDSRouteConfiguration,
// 		XDSOther,
// 		// RoutesReachable,
// 	)
// }

const (
	AuthenticateService = Check("authenticate.service")

	AuthorizationService = Check("authorize.service")

	EnvoyProcess = Check("envoy.process")

	ProxyService = Check("proxy.service")

	// BuildDatabrokerConfig checks whether the Databroker config was applied
	DatabrokerBuildConfig = Check("config.databroker.build")
	// DatabrokerInitialSync checks whether the initial sync was applied
	DatabrokerInitialSync = Check("databroker.sync.initial")

	// CollectAndSendTelemetry checks whether telemetry was collected and sent
	CollectAndSendTelemetry = Check("zero.telemetry.collect-and-send")
	// StorageBackend checks whether the storage backend is healthy
	StorageBackend = Check("storage.backend")

	StorageBackendCleanup = Check("storage.backend.cleanup")

	StorageBackendNotification = Check("storage.backend.notifications")

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
