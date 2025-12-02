package envoyversion

import (
	"runtime/debug"
	"strings"

	"golang.org/x/mod/module"

	_ "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh" // to get version info
)

// Version returns the envoy version.
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	var modVersion string
	for _, dep := range info.Deps {
		if dep.Path == "github.com/pomerium/envoy-custom" {
			if dep.Replace != nil {
				modVersion = dep.Replace.Version
			} else {
				modVersion = dep.Version
			}
			break
		}
	}

	if module.IsPseudoVersion(modVersion) {
		if base, err := module.PseudoVersionBase(modVersion); err == nil {
			modVersion = base
		}
	}

	return strings.TrimPrefix(modVersion, "v")
}
