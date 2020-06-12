// Package directory implements the user group directory service.
package directory

import (
	"context"
	"net/url"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/directory/azure"
	"github.com/pomerium/pomerium/internal/directory/gitlab"
	"github.com/pomerium/pomerium/internal/directory/google"
	"github.com/pomerium/pomerium/internal/directory/okta"
	"github.com/pomerium/pomerium/internal/directory/onelogin"
	"github.com/pomerium/pomerium/internal/grpc/directory"
	"github.com/pomerium/pomerium/internal/log"
)

// A User is a directory User.
type User = directory.User

// A Provider provides user group directory information.
type Provider interface {
	UserGroups(ctx context.Context) ([]*User, error)
}

// GetProvider gets the provider for the given options.
func GetProvider(options *config.Options) Provider {
	switch options.Provider {
	case "azure":
		serviceAccount, err := azure.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return azure.New(azure.WithServiceAccount(serviceAccount))
		}

		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for azure directory provider")
	case "gitlab":
		serviceAccount, err := gitlab.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return gitlab.New(gitlab.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for gitlab directory provider")
	case "google":
		if options.ServiceAccount != "" {
			return google.New(google.WithServiceAccount(options.ServiceAccount))
		}
	case "okta":
		providerURL, _ := url.Parse(options.ProviderURL)
		serviceAccount, err := okta.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return okta.New(
				okta.WithProviderURL(providerURL),
				okta.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for okta directory provider")
	case "onelogin":
		serviceAccount, err := onelogin.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return onelogin.New(onelogin.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for onelogin directory provider")
	}

	log.Warn().
		Str("provider", options.Provider).
		Msg("no directory provider implementation found, disabling support for groups")
	return nullProvider{}
}

type nullProvider struct{}

func (nullProvider) UserGroups(ctx context.Context) ([]*User, error) {
	return nil, nil
}
