package envoyversion

import (
	"runtime/debug"

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

	// If the version is tagged, the corresponding image will have that exact tag.
	// If the version is a pseudo-version, the image tag will exactly match the
	// "yyyymmddhhmmss-abcdef123456" part of the pseudo-version string.
	if module.IsPseudoVersion(modVersion) {
		t, _ := module.PseudoVersionTime(modVersion)
		rev, _ := module.PseudoVersionRev(modVersion)
		return t.UTC().Format(module.PseudoVersionTimestampFormat) + "-" + rev
	}

	return modVersion
}
