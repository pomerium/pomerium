//go:build embed_pomerium || debug_local_envoy

package files

var rawBinary []byte

var rawChecksum string

var rawVersion string

// SetFiles sets external source for envoy
func SetFiles(bin []byte, checksum, version string) {
	rawBinary = bin
	rawChecksum = checksum
	rawVersion = version
}
