// Package secrets wires the secret-injection subsystem together. Its
// DefaultRegistry is the single source of truth for which backend schemes are
// bindable, used by both config validation and the authorize runtime so the
// two never disagree.
package secrets

import (
	"github.com/pomerium/pomerium/pkg/secrets/file"
	"github.com/pomerium/pomerium/pkg/secrets/provider"
)

// DefaultRegistry returns a provider.Registry with every built-in scheme
// registered. v1 registers only file://. Each call returns an independent,
// fully-usable registry.
func DefaultRegistry() *provider.Registry {
	reg := provider.NewRegistry()
	mustRegister(reg, file.New())
	return reg
}

func mustRegister(reg *provider.Registry, p provider.Provider) {
	if err := reg.Register(p); err != nil {
		// Registration only fails on a duplicate scheme, which is a programming
		// error in a fresh registry.
		panic(err)
	}
}
