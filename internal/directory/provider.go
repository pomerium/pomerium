// Package directory implements the user group directory service.
package directory

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/google/go-cmp/cmp"

	"github.com/pomerium/pomerium/internal/directory/auth0"
	"github.com/pomerium/pomerium/internal/directory/azure"
	"github.com/pomerium/pomerium/internal/directory/github"
	"github.com/pomerium/pomerium/internal/directory/gitlab"
	"github.com/pomerium/pomerium/internal/directory/google"
	"github.com/pomerium/pomerium/internal/directory/okta"
	"github.com/pomerium/pomerium/internal/directory/onelogin"
	"github.com/pomerium/pomerium/internal/directory/ping"
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

	ctx := context.TODO()
	if globalProvider.provider != nil && cmp.Equal(globalProvider.options, options) {
		log.Debug(ctx).Str("provider", options.Provider).Msg("directory: no change detected, reusing existing directory provider")
		return globalProvider.provider
	}
	defer func() {
		globalProvider.provider = provider
		globalProvider.options = options
	}()

	var providerURL *url.URL
	// url.Parse will succeed even if we pass an empty string
	if options.ProviderURL != "" {
		providerURL, _ = url.Parse(options.ProviderURL)
	}
	var errSyncDisabled error
	switch options.Provider {
	case auth0.Name:
		serviceAccount, err := auth0.ParseServiceAccount(options)
		if err == nil {
			return auth0.New(
				auth0.WithDomain(options.ProviderURL),
				auth0.WithServiceAccount(serviceAccount))
		}
		errSyncDisabled = fmt.Errorf("invalid auth0 service account: %w", err)
		log.Warn(ctx).
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for auth0 directory provider")
	case azure.Name:
		serviceAccount, err := azure.ParseServiceAccount(options)
		if err == nil {
			return azure.New(azure.WithServiceAccount(serviceAccount))
		}
		errSyncDisabled = fmt.Errorf("invalid Azure service account: %w", err)
		log.Warn(ctx).
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for azure directory provider")
	case github.Name:
		serviceAccount, err := github.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return github.New(github.WithServiceAccount(serviceAccount))
		}
		errSyncDisabled = fmt.Errorf("invalid GitHub service account: %w", err)
		log.Warn(ctx).
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
		errSyncDisabled = fmt.Errorf("invalid GitLab service account: %w", err)
		log.Warn(ctx).
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for gitlab directory provider")
	case google.Name:
		serviceAccount, err := google.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			googleOptions := []google.Option{
				google.WithServiceAccount(serviceAccount),
			}
			if options.ProviderURL != "" {
				googleOptions = append(googleOptions, google.WithURL(options.ProviderURL))
			}
			return google.New(googleOptions...)
		}
		errSyncDisabled = fmt.Errorf("invalid google service account: %w", err)
		log.Warn(ctx).
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for Google directory provider")
	case okta.Name:
		serviceAccount, err := okta.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return okta.New(
				okta.WithProviderURL(providerURL),
				okta.WithServiceAccount(serviceAccount))
		}
		errSyncDisabled = fmt.Errorf("invalid Okta service account: %w", err)
		log.Warn(ctx).
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for okta directory provider")
	case onelogin.Name:
		serviceAccount, err := onelogin.ParseServiceAccount(options.ServiceAccount)
		if err == nil {
			return onelogin.New(onelogin.WithServiceAccount(serviceAccount))
		}
		errSyncDisabled = fmt.Errorf("invalid OneLogin service account: %w", err)
		log.Warn(ctx).
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
		errSyncDisabled = fmt.Errorf("invalid Ping service account: %w", err)
		log.Warn(ctx).
			Str("service", "directory").
			Str("provider", options.Provider).
			Err(err).
			Msg("invalid service account for ping directory provider")
	case "":
		errSyncDisabled = fmt.Errorf("no directory provider configured")
	default:
		errSyncDisabled = fmt.Errorf("unknown directory provider %s", options.Provider)
	}

	log.Warn(ctx).
		Str("provider", options.Provider).
		Msg(errSyncDisabled.Error())
	return nullProvider{errSyncDisabled}
}

type nullProvider struct {
	error
}

func (p nullProvider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	return nil, p.error
}

func (p nullProvider) UserGroups(ctx context.Context) ([]*Group, []*User, error) {
	return nil, nil, p.error
}
