// Package files contains files for use with envoy.
package files

import (
	_ "embed" // for embedded files
	"strings"
)

// Binary returns the raw envoy binary bytes.
func Binary() []byte {
	return rawBinary
}

// Checksum returns the checksum for the embedded envoy binary.
func Checksum() string {
	return strings.Fields(rawChecksum)[0]
}

// FullVersion returns the full version string for envoy.
func FullVersion() string {
	return Version() + "+" + Checksum()
}

// Version returns the envoy version.
func Version() string {
	return strings.TrimSpace(rawVersion)
}
