//go:build darwin && arm64 && !embed_pomerium
// +build darwin,arm64,!embed_pomerium

package files

import _ "embed" // embed

//go:embed envoy-darwin-arm64
var rawBinary []byte

//go:embed envoy-darwin-arm64.sha256
var rawChecksum string

//go:embed envoy-darwin-arm64.version
var rawVersion string
