//go:build linux && arm64 && !embed_pomerium && !debug_local_envoy

package files

import _ "embed" // embed

//go:embed envoy-linux-arm64
var rawBinary []byte

//go:embed envoy-linux-arm64.lock
var rawLockfile []byte
