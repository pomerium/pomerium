//go:build embed_pomerium || debug_local_envoy

package files

var rawBinary []byte

var rawLockfile []byte

// SetFiles sets external source for envoy
func SetFiles(bin []byte, lockfile []byte) {
	rawBinary = bin
	rawLockfile = lockfile
}
