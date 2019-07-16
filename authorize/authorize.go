package authorize // import "github.com/pomerium/pomerium/authorize"

import (
	"encoding/base64"
	"fmt"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/metrics"
)

// ValidateOptions checks to see if configuration values are valid for the
// authorize service. Returns first error, if found.
func ValidateOptions(o config.Options) error {
	decoded, err := base64.StdEncoding.DecodeString(o.SharedKey)
	if err != nil {
		return fmt.Errorf("authorize: `SHARED_SECRET` setting is invalid base64: %v", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("authorize: `SHARED_SECRET` want 32 but got %d bytes", len(decoded))
	}
	return nil
}

// Authorize struct holds
type Authorize struct {
	SharedKey string

	identityAccess IdentityValidator
	// contextValidator
	// deviceValidator
}

// New validates and creates a new Authorize service from a set of Options
func New(opts config.Options) (*Authorize, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	// errors handled by validate
	sharedKey, _ := base64.StdEncoding.DecodeString(opts.SharedKey)
	return &Authorize{
		SharedKey:      string(sharedKey),
		identityAccess: NewIdentityWhitelist(opts.Policies, opts.Administrators),
	}, nil
}

// NewIdentityWhitelist returns an indentity validator.
// todo(bdd) : a radix-tree implementation is probably more efficient
func NewIdentityWhitelist(policies []config.Policy, admins []string) IdentityValidator {
	metrics.AddPolicyCountCallback("authorize", func() int64 {
		return int64(len(policies))
	})
	return newIdentityWhitelistMap(policies, admins)
}

// ValidIdentity returns if an identity is authorized to access a route resource.
func (a *Authorize) ValidIdentity(route string, identity *Identity) bool {
	return a.identityAccess.Valid(route, identity)
}

// UpdateOptions updates internal structures based on config.Options
func (a *Authorize) UpdateOptions(o config.Options) error {
	log.Info().Msg("authorize: updating options")
	a.identityAccess = NewIdentityWhitelist(o.Policies, o.Administrators)
	return nil
}
