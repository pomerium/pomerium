package generator

import (
	"regexp"
	"strconv"
)

// Version is the generated rego language version number. When changed it means the contract between authorize and rego
// has changed in a breaking way, so older versions of Pomerium should not run the newer code.
const Version = 1

var versionRE = regexp.MustCompile(`package pomerium.policy #version=([0-9]+)`)

// GetVersionFromRego gets the generator version from rego. If no version is found the current version is returned.
func GetVersionFromRego(rawRego string) int {
	matches := versionRE.FindStringSubmatch(rawRego)
	if len(matches) < 2 {
		return Version
	}
	v, err := strconv.Atoi(matches[1])
	if err != nil {
		return Version
	}
	return v
}
