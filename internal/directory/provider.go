// Package directory implements the user group directory service.
package directory

import (
	"context"
	"fmt"
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
func GetProvider(ctx context.Context, options Options) Provider {
	globalProvider.Lock()
	defer globalProvider.Unlock()

	if globalProvider.provider != nil && cmp.Equal(globalProvider.options, options) {
		return globalProvider.provider
	}

	provider, err := getProviderLocked(options)
	if err != nil {
		log.Error(ctx).Err(err).Msg("disabling support for groups")
		provider = nullProvider{}
	}

	globalProvider.provider = provider
	globalProvider.options = options

	return provider
}

func getProviderLocked(options Options) (Provider, error) {
	var providerURL *url.URL
	// url.Parse will succeed even if we pass an empty string
	if options.ProviderURL != "" {
		providerURL, _ = url.Parse(options.ProviderURL)
	}
	switch options.Provider {
	case auth0.Name:
		serviceAccount, err := auth0.ParseServiceAccount(options)
		if err != nil {
			return nil, fmt.Errorf("auth0: invalid service account: %w", err)
		}
		return auth0.New(
			auth0.WithDomain(options.ProviderURL),
			auth0.WithServiceAccount(serviceAccount)), nil
	case azure.Name:
		serviceAccount, err := azure.ParseServiceAccount(options)
		if err != nil {
			return nil, fmt.Errorf("azure: invalid service account: %w", err)
		}
		return azure.New(azure.WithServiceAccount(serviceAccount)), nil
	case github.Name:
		serviceAccount, err := github.ParseServiceAccount(options.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("github: invalid service account: %w", err)
		}
		return github.New(github.WithServiceAccount(serviceAccount)), nil
	case gitlab.Name:
		serviceAccount, err := gitlab.ParseServiceAccount(options.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("gitlab: invalid service account: %w", err)
		}
		if providerURL == nil {
			return gitlab.New(gitlab.WithServiceAccount(serviceAccount)), nil
		}
		return gitlab.New(
			gitlab.WithURL(providerURL),
			gitlab.WithServiceAccount(serviceAccount)), nil
	case google.Name:
		serviceAccount, err := google.ParseServiceAccount(options.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("google: invalid service account: %w", err)
		}
		return google.New(google.WithServiceAccount(serviceAccount)), nil
	case okta.Name:
		serviceAccount, err := okta.ParseServiceAccount(options.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("okta: invalid service account: %w", err)
		}
		return okta.New(
			okta.WithProviderURL(providerURL),
			okta.WithServiceAccount(serviceAccount)), nil
	case onelogin.Name:
		serviceAccount, err := onelogin.ParseServiceAccount(options.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("onelogin: invalid service account: %w", err)
		}
		return onelogin.New(onelogin.WithServiceAccount(serviceAccount)), nil
	case ping.Name:
		serviceAccount, err := ping.ParseServiceAccount(options.ServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("ping: invalid service account: %w", err)
		}
		return ping.New(
			ping.WithProviderURL(providerURL),
			ping.WithServiceAccount(serviceAccount)), nil
	}

	return nil, fmt.Errorf("invalid identity provider %v", options.Provider)
}

type nullProvider struct{}

func (nullProvider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	return nil, nil
}

func (nullProvider) UserGroups(ctx context.Context) ([]*Group, []*User, error) {
	return nil, nil, nil
}
