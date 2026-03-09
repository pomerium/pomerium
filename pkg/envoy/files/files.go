// Package files contains files for use with envoy.
package files

import (
	_ "embed" // for embedded files
	"encoding/json"

	"github.com/pomerium/pomerium/pkg/envoy/envoyversion"
)

// Binary returns the raw envoy binary bytes.
func Binary() []byte {
	return rawBinary
}

// Lockfile returns the embedded lockfile describing the envoy binary.
func Lockfile() envoyversion.Lockfile {
	var lockfile envoyversion.Lockfile
	if err := json.Unmarshal(rawLockfile, &lockfile); err != nil {
		panic(err)
	}
	return lockfile
}
