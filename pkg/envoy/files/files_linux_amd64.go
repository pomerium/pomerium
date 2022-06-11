//go:build linux && amd64 && !embed_pomerium
// +build linux,amd64,!embed_pomerium

package files

import _ "embed" // embed

//go:embed envoy-linux-amd64
var rawBinary []byte

//go:embed envoy-linux-amd64.sha256
var rawChecksum string

//go:embed envoy-linux-amd64.version
var rawVersion string
