//go:build postgres_cli_e2e

package pomerium

import "github.com/pomerium/pomerium/pkg/enterprise/capability"

// WithPostgresManagedVerifierForE2E replaces managed-PostgreSQL entitlement
// verification for one Pomerium instance built with the postgres_cli_e2e tag.
// It exists only to let the black-box CLI test exercise the customer path
// without embedding production license material in CI.
func WithPostgresManagedVerifierForE2E(verifier capability.ManagedPostgresVerifier) Option {
	return func(options *Options) {
		options.postgresManagedVerifier = verifier
	}
}
