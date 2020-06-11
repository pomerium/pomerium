// Package google contains the Google directory provider.
package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"

	"github.com/pomerium/pomerium/internal/grpc/directory"
	"github.com/pomerium/pomerium/internal/log"
)

const (
	defaultProviderURL = "https://accounts.google.com"
)

type config struct {
	serviceAccount string
	url            string
}

// An Option changes the configuration for the Google directory provider.
type Option func(cfg *config)

// WithServiceAccount sets the service account in the Google configuration.
func WithServiceAccount(serviceAccount string) Option {
	return func(cfg *config) {
		cfg.serviceAccount = serviceAccount
	}
}

// WithURL sets the provider url to use.
func WithURL(url string) Option {
	return func(cfg *config) {
		cfg.url = url
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithURL(defaultProviderURL)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// Required scopes for groups api
// https://developers.google.com/admin-sdk/directory/v1/reference/groups/list
var apiScopes = []string{admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope}

// A Provider is a Google directory provider.
type Provider struct {
	cfg *config
	log zerolog.Logger

	mu        sync.RWMutex
	apiClient *admin.Service
}

// New creates a new Google directory provider.
func New(options ...Option) *Provider {
	return &Provider{
		cfg: getConfig(options...),
		log: log.With().Str("service", "directory").Str("provider", "google").Logger(),
	}
}

// UserGroups returns a slice of group names a given user is in
// NOTE: groups via Directory API is limited to 1 QPS!
// https://developers.google.com/admin-sdk/directory/v1/reference/groups/list
// https://developers.google.com/admin-sdk/directory/v1/limits
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.User, error) {
	apiClient, err := p.getAPIClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("google: error getting API client: %w", err)
	}

	var groups []string
	err = apiClient.Groups.List().
		Context(ctx).
		Customer("my_customer").
		Pages(ctx, func(res *admin.Groups) error {
			for _, g := range res.Groups {
				groups = append(groups, g.Id)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("google: error getting groups: %w", err)
	}

	userEmailToGroups := map[string][]string{}
	for _, group := range groups {
		group := group
		err = apiClient.Members.List(group).
			Context(ctx).
			Pages(ctx, func(res *admin.Members) error {
				for _, member := range res.Members {
					userEmailToGroups[member.Email] = append(userEmailToGroups[member.Email], group)
				}
				return nil
			})
		if err != nil {
			return nil, fmt.Errorf("google: error getting group members: %w", err)
		}
	}

	var users []*directory.User
	for userEmail, groups := range userEmailToGroups {
		sort.Strings(groups)
		users = append(users, &directory.User{
			Id:     userEmail,
			Groups: groups,
		})
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].Id < users[j].Id
	})
	return users, nil
}

func (p *Provider) getAPIClient(ctx context.Context) (*admin.Service, error) {
	p.mu.RLock()
	apiClient := p.apiClient
	p.mu.RUnlock()
	if apiClient != nil {
		return apiClient, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.apiClient != nil {
		return p.apiClient, nil
	}

	apiCreds, err := base64.StdEncoding.DecodeString(p.cfg.serviceAccount)
	if err != nil {
		return nil, fmt.Errorf("google: could not decode service account json %w", err)
	}

	var additionalFields struct {
		ImpersonateUser string `json:"impersonate_user"`
	}
	_ = json.Unmarshal(apiCreds, &additionalFields)

	config, err := google.JWTConfigFromJSON(apiCreds, apiScopes...)
	if err != nil {
		return nil, fmt.Errorf("google: error reading jwt config: %w", err)
	}
	config.Subject = additionalFields.ImpersonateUser

	ts := config.TokenSource(ctx)

	p.apiClient, err = admin.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		return nil, fmt.Errorf("google: failed creating admin service %w", err)
	}
	return p.apiClient, nil
}
