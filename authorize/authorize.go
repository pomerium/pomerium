package authorize // import "github.com/pomerium/pomerium/authorize"

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/pomerium/pomerium/internal/config"

	"github.com/pomerium/pomerium/internal/policy"
)

// ValidateOptions checks to see if configuration values are valid for the
// authorize service. Returns first error, if found.
func ValidateOptions(o *config.Options) error {
	decoded, err := base64.StdEncoding.DecodeString(o.SharedKey)
	if err != nil {
		return fmt.Errorf("authorize: `SHARED_SECRET` setting is invalid base64: %v", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("authorize: `SHARED_SECRET` want 32 but got %d bytes", len(decoded))
	}
	if o.Policy == "" && o.PolicyFile == "" {
		return errors.New("authorize: either `POLICY` or `POLICY_FILE` must be non-nil")
	}
	if o.Policy != "" {
		confBytes, err := base64.StdEncoding.DecodeString(o.Policy)
		if err != nil {
			return fmt.Errorf("authorize: `POLICY` is invalid base64 %v", err)
		}
		_, err = policy.FromConfig(confBytes)
		if err != nil {
			return fmt.Errorf("authorize: `POLICY` %v", err)
		}
	}
	if o.PolicyFile != "" {
		_, err = policy.FromConfigFile(o.PolicyFile)
		if err != nil {
			return fmt.Errorf("authorize: `POLICY_FILE` %v", err)
		}
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
func New(opts *config.Options) (*Authorize, error) {
	if opts == nil {
		return nil, errors.New("authorize: options cannot be nil")
	}
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	// errors handled by validate
	sharedKey, _ := base64.StdEncoding.DecodeString(opts.SharedKey)
	var policies []policy.Policy
	if opts.Policy != "" {
		confBytes, _ := base64.StdEncoding.DecodeString(opts.Policy)
		policies, _ = policy.FromConfig(confBytes)
	} else {
		policies, _ = policy.FromConfigFile(opts.PolicyFile)
	}

	return &Authorize{
		SharedKey:      string(sharedKey),
		identityAccess: NewIdentityWhitelist(policies),
	}, nil
}

// ValidIdentity returns if an identity is authorized to access a route resource.
func (a *Authorize) ValidIdentity(route string, identity *Identity) bool {
	return a.identityAccess.Valid(route, identity)
}

// NewIdentityWhitelist returns an indentity validator.
// todo(bdd) : a radix-tree implementation is probably more efficient
func NewIdentityWhitelist(policies []policy.Policy) IdentityValidator {
	return newIdentityWhitelistMap(policies)
}
