//go:build darwin && amd64 && !embed_pomerium && !debug_local_envoy

package files

import _ "embed" // embed

//go:embed envoy-darwin-amd64
var rawBinary []byte

//go:embed envoy-darwin-amd64.sha256
var rawChecksum string

//go:embed envoy-darwin-amd64.version
var rawVersion string
