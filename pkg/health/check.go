package health

import (
	"fmt"
	"strings"
	"sync"

	"github.com/samber/lo"
)

type Check string

var (
	defaultCheckMu = &sync.RWMutex{}
	defaultChecks  = map[Check]struct{}{}
)

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

func init() {
	SetDefaultExpected(
		BuildDatabrokerConfig,
		CollectAndSendTelemetry,
		StorageBackend,
		XDSCluster,
		XDSListener,
		XDSRouteConfiguration,
		XDSOther,
		RoutesReachable,
	)
}

type Status int

const (
	StatusStarted Status = iota
	StatusRunning
	StatusTerminating
	StatusError
)

func (s Status) String() string {
	v := "unkown"
	switch s {
	case StatusStarted:
		v = "started"
	case StatusRunning:
		v = "running"
	case StatusTerminating:
		v = "terminating"
	case StatusError:
		v = "error"
	}
	return strings.ToUpper(v)
}

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
	RoutesReachable = Check("routes.reachable")
)

// ZeroResourceBundle checks whether the Zero resource bundle was applied
func ZeroResourceBundle(bundleID string) Check {
	return Check(fmt.Sprintf("zero.resource-bundle.%s", bundleID))
}
