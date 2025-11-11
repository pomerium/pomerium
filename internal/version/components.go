package version

import (
	_ "embed"
	"encoding/json"

	"github.com/pomerium/pomerium/pkg/envoy/files"
)

//go:embed components.json
var componentsJSON []byte

// Components returns the versions of components in pomerium.
func Components() map[string]string {
	m := map[string]string{
		"envoy": files.FullVersion(),
	}
	err := json.Unmarshal(componentsJSON, &m)
	if err != nil {
		panic(err)
	}
	return m
}
