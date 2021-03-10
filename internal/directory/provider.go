// Package directory implements the user group directory service.
package directory

import (
	"context"
	"net/url"
	"sync"

	"github.com/google/go-cmp/cmp"

	"github.com/pomerium/pomerium/internal/directory/ping"

	"github.com/pomerium/pomerium/internal/directory/auth0"
	"github.com/pomerium/pomerium/internal/directory/azure"
	"github.com/pomerium/pomerium/internal/directory/github"
	"github.com/pomerium/pomerium/internal/directory/gitlab"
	"github.com/pomerium/pomerium/internal/directory/google"
	"github.com/pomerium/pomerium/internal/directory/okta"
	"github.com/pomerium/pomerium/internal/directory/onelogin"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// A Group is a directory Group.
type Group = directory.Group

// A User is a directory User.
type User = directory.User

// Options are the options specific to the provider.
type Options = directory.Options

// RegisterDirectoryServiceServer registers the directory gRPC service.
var RegisterDirectoryServiceServer = directory.RegisterDirectoryServiceServer

// A Provider provides user group directory information.
type Provider interface {
	User(ctx context.Context, userID, accessToken string) (*User, error)
	UserGroups(ctx context.Context) ([]*Group, []*User, error)
}

var globalProvider = struct {
	sync.Mutex
	provider Provider
	options  Options
}{}

// GetProvider gets the provider for the given options.
func GetProvider(options Options) (provider Provider) {
	globalProvider.Lock()
	defer globalProvider.Unlock()

	if globalProvider.provider != nil && cmp.Equal(globalProvider.options, options) {
		log.Debug().Str("provider", options.Provider).Msg("directory: no change detected, reusing existing directory provider")
		return globalProvider.provider
	}
	defer func() {
		globalProvider.provider = provider
		globalProvider.options = options
	}()

	providerURL, _ := url.Parse(options.ProviderURL)
	switch options.Provider {
	case auth0.Name:
		serviceAccount, err := auth0.ParseServiceAccount(options)
		if err == nil {
			return auth0.New(
				auth0.WithDomain(options.ProviderURL),
				auth0.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for auth0 directory provider")
	case azure.Name:
		serviceAccount, err := azure.ParseServiceAccount(options)
		if err == nil {
			return azure.New(azure.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for azure directory provider")
	case github.Name:
		serviceAccount, err := github.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return github.New(github.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for github directory provider")
	case gitlab.Name:
		serviceAccount, err := gitlab.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			if providerURL == nil {
				return gitlab.New(gitlab.WithServiceAccount(serviceAccount))
			}
			return gitlab.New(
				gitlab.WithURL(providerURL),
				gitlab.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for gitlab directory provider")
	case google.Name:
		serviceAccount, err := google.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return google.New(google.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for google directory provider")
	case okta.Name:
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
	case onelogin.Name:
		serviceAccount, err := onelogin.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return onelogin.New(onelogin.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for onelogin directory provider")
	case ping.Name:
		serviceAccount, err := ping.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return ping.New(
				ping.WithProviderURL(providerURL),
				ping.WithServiceAccount(serviceAccount))
		}
		log.Warn().
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for ping directory provider")
	}

	log.Warn().
		Str("provider", options.Provider).
		Msg("no directory provider implementation found, disabling support for groups")
	return nullProvider{}
}

type nullProvider struct{}

func (nullProvider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	return nil, nil
}

func (nullProvider) UserGroups(ctx context.Context) ([]*Group, []*User, error) {
	return nil, nil, nil
}
