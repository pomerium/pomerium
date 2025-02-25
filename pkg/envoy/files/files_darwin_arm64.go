//go:build darwin && arm64 && !embed_pomerium && !debug_local_envoy
// +build darwin,arm64,!embed_pomerium,!debug_local_envoy

package files

import _ "embed" // embed

//go:embed envoy
var rawBinary []byte

//go:embed envoy.sha256
var rawChecksum string

//go:embed envoy.version
var rawVersion string
