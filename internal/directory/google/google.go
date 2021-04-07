// Package google contains the Google directory provider.
package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

const (
	// Name is the provider name.
	Name = "google"

	currentAccountCustomerID = "my_customer"
)

const (
	defaultProviderURL = "https://www.googleapis.com/"
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

// User returns the user record for the given id.
func (p *Provider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	apiClient, err := p.getAPIClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("google: error getting API client: %w", err)
	}

	du := &directory.User{
		Id: userID,
	}

	au, err := apiClient.Users.Get(userID).
		Context(ctx).
		Do()
	if isAccessDenied(err) {
		// ignore forbidden errors as a user may login from another gsuite domain
		return du, nil
	} else if err != nil {
		return nil, fmt.Errorf("google: error getting user: %w", err)
	} else {
		if au.Name != nil {
			du.DisplayName = au.Name.FullName
		}
		du.Email = au.PrimaryEmail
	}

	err = apiClient.Groups.List().
		Context(ctx).
		UserKey(userID).
		Pages(ctx, func(res *admin.Groups) error {
			for _, g := range res.Groups {
				du.GroupIds = append(du.GroupIds, g.Id)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("google: error getting groups for user: %w", err)
	}

	sort.Strings(du.GroupIds)

	return du, nil
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
		Customer(currentAccountCustomerID).
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

	userLookup := map[string]apiUserObject{}
	err = apiClient.Users.List().
		Context(ctx).
		Customer(currentAccountCustomerID).
		Pages(ctx, func(res *admin.Users) error {
			for _, u := range res.Users {
				auo := apiUserObject{
					ID:    u.Id,
					Email: u.PrimaryEmail,
				}
				if u.Name != nil {
					auo.DisplayName = u.Name.FullName
				}
				userLookup[u.Id] = auo
			}
			return nil
		})
	if err != nil {
		return nil, nil, fmt.Errorf("google: error getting users: %w", err)
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
	for _, u := range userLookup {
		groups := userIDToGroups[u.ID]
		sort.Strings(groups)
		users = append(users, &directory.User{
			Id:          u.ID,
			GroupIds:    groups,
			DisplayName: u.DisplayName,
			Email:       u.Email,
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

	p.apiClient, err = admin.NewService(ctx, option.WithTokenSource(ts), option.WithEndpoint(p.cfg.url))
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

type apiUserObject struct {
	ID          string
	DisplayName string
	Email       string
}

func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}

	gerr := new(googleapi.Error)
	if errors.As(err, &gerr) {
		return gerr.Code == http.StatusForbidden
	}

	return false
}
