package health

type Check string

const (
	// XDSCluster checks whether the XDS Cluster resources were applied
	XDSCluster = Check("xds.cluster")
	// XDSListener checks whether the XDS Listener resources were applied
	XDSListener = Check("xds.listener")
	// XDSRouteConfiguration checks whether the XDS RouteConfiguration resources were applied
	XDSRouteConfiguration = Check("xds.route-configuration")
	// XDSOther is a catch-all for other XDS resources
	XDSOther = Check("xds.other")
)
