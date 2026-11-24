package analytics

import "sync/atomic"

var envoyBuildInformation atomic.Pointer[func() (string, string)]

func init() {
	envoyBuildInformation.Store(new(func() (version, license string) { return "", "" }))
}

// SetEnvoyBuildInformation sets the envoy build information function. This is
// done to avoid this package automatically including envoy.
func SetEnvoyBuildInformation(fn func() (version, license string)) {
	envoyBuildInformation.Store(new(fn))
}
