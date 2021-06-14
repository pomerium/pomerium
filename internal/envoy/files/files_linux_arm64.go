//+build linux,arm64

package files

import _ "embed" // embed

//go:embed envoy-linux-arm64
var rawBinary []byte

//go:embed envoy-linux-arm64.sha256
var rawChecksum string

//go:embed envoy-linux-arm64.version
var rawVersion string
