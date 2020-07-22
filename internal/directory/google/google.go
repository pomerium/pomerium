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

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// Name is the provider name.
const Name = "google"

const (
	defaultProviderURL = "https://accounts.google.com"
)

type config struct {
	serviceAccount *ServiceAccount
	url            string
}

// An Option changes the configuration for the Google directory provider.
type Option func(cfg *config)

// WithServiceAccount sets the service account in the Google configuration.
func WithServiceAccount(serviceAccount *ServiceAccount) Option {
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
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	apiClient, err := p.getAPIClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("google: error getting API client: %w", err)
	}

	var groups []*directory.Group
	err = apiClient.Groups.List().
		Context(ctx).
		Customer("my_customer").
		Pages(ctx, func(res *admin.Groups) error {
			for _, g := range res.Groups {
				// Skip group without member.
				if g.DirectMembersCount == 0 {
					continue
				}
				groups = append(groups, &directory.Group{
					Id:    g.Id,
					Name:  g.Email,
					Email: g.Email,
				})
			}
			return nil
		})
	if err != nil {
		return nil, nil, fmt.Errorf("google: error getting groups: %w", err)
	}

	userIDToGroups := map[string][]string{}
	for _, group := range groups {
		group := group
		err = apiClient.Members.List(group.Id).
			Context(ctx).
			Pages(ctx, func(res *admin.Members) error {
				for _, member := range res.Members {
					userIDToGroups[member.Id] = append(userIDToGroups[member.Id], group.Id)
				}
				return nil
			})
		if err != nil {
			return nil, nil, fmt.Errorf("google: error getting group members: %w", err)
		}
	}

	var users []*directory.User
	for userID, groups := range userIDToGroups {
		sort.Strings(groups)
		users = append(users, &directory.User{
			Id:       databroker.GetUserID(Name, userID),
			GroupIds: groups,
		})
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].Id < users[j].Id
	})
	return groups, users, nil
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

	apiCreds, err := json.Marshal(p.cfg.serviceAccount)
	if err != nil {
		return nil, fmt.Errorf("google: could not marshal service account json %w", err)
	}

	config, err := google.JWTConfigFromJSON(apiCreds, apiScopes...)
	if err != nil {
		return nil, fmt.Errorf("google: error reading jwt config: %w", err)
	}
	config.Subject = p.cfg.serviceAccount.ImpersonateUser

	ts := config.TokenSource(ctx)

	p.apiClient, err = admin.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		return nil, fmt.Errorf("google: failed creating admin service %w", err)
	}
	return p.apiClient, nil
}

// A ServiceAccount is used to authenticate with the Google APIs.
//
// Google oauth fields are from https://github.com/golang/oauth2/blob/master/google/google.go#L99
type ServiceAccount struct {
	Type string `json:"type"` // serviceAccountKey or userCredentialsKey

	// Service Account fields
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURL     string `json:"token_uri"`
	ProjectID    string `json:"project_id"`

	// User Credential fields
	// (These typically come from gcloud auth.)
	ClientSecret string `json:"client_secret"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`

	// The User to use for Admin Directory API calls
	ImpersonateUser string `json:"impersonate_user"`
}

// ParseServiceAccount parses the service account in the config options.
func ParseServiceAccount(rawServiceAccount string) (*ServiceAccount, error) {
	bs, err := base64.StdEncoding.DecodeString(rawServiceAccount)
	if err != nil {
		return nil, err
	}

	var serviceAccount ServiceAccount
	err = json.Unmarshal(bs, &serviceAccount)
	if err != nil {
		return nil, err
	}

	if serviceAccount.ImpersonateUser == "" {
		return nil, fmt.Errorf("impersonate_user is required")
	}

	return &serviceAccount, nil
}
