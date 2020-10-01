// Package auth0 contains the Auth0 directory provider.
// Note that Auth0 refers to groups as roles.
package auth0

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"

	"gopkg.in/auth0.v4/management"
)

// Name is the provider name.
const Name = "auth0"

// RoleManager defines what is needed to get role info from Auth0.
type RoleManager interface {
	List(opts ...management.ListOption) (r *management.RoleList, err error)
	Users(id string, opts ...management.ListOption) (u *management.UserList, err error)
}

type config struct {
	domain         string
	serviceAccount *ServiceAccount
	newRoleManager func(ctx context.Context, domain string, serviceAccount *ServiceAccount) (RoleManager, error)
}

// Option provides config for the Auth0 Provider.
type Option func(cfg *config)

// WithServiceAccount sets the service account option.
func WithServiceAccount(serviceAccount *ServiceAccount) Option {
	return func(cfg *config) {
		cfg.serviceAccount = serviceAccount
	}
}

// WithDomain sets the provider domain option.
func WithDomain(domain string) Option {
	return func(cfg *config) {
		cfg.domain = domain
	}
}

func defaultNewRoleManagerFunc(ctx context.Context, domain string, serviceAccount *ServiceAccount) (RoleManager, error) {
	m, err := management.New(domain, serviceAccount.ClientID, serviceAccount.Secret, management.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("auth0: could not build management")
	}
	return m.Role, nil
}

func getConfig(options ...Option) *config {
	cfg := &config{
		newRoleManager: defaultNewRoleManagerFunc,
	}
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// Provider is an Auth0 user group directory provider.
type Provider struct {
	cfg *config
	log zerolog.Logger
}

// New creates a new Provider.
func New(options ...Option) *Provider {
	return &Provider{
		cfg: getConfig(options...),
		log: log.With().Str("service", "directory").Str("provider", "auth0").Logger(),
	}
}

func (p *Provider) getRoleManager(ctx context.Context) (RoleManager, error) {
	return p.cfg.newRoleManager(ctx, p.cfg.domain, p.cfg.serviceAccount)
}

// UserGroups fetches a slice of groups and users.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	rm, err := p.getRoleManager(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("auth0: could not get the role manager: %w", err)
	}

	roles, err := getRoles(rm)
	if err != nil {
		return nil, nil, fmt.Errorf("auth0: %w", err)
	}

	userIDToGroups := map[string][]string{}
	for _, role := range roles {
		ids, err := getRoleUserIDs(rm, role.Id)
		if err != nil {
			return nil, nil, fmt.Errorf("auth0: %w", err)
		}

		for _, id := range ids {
			userIDToGroups[id] = append(userIDToGroups[id], role.Id)
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
	return roles, users, nil
}

func getRoles(rm RoleManager) ([]*directory.Group, error) {
	roles := []*directory.Group{}

	shouldContinue := true
	page := 0

	for shouldContinue {
		listRes, err := rm.List(management.IncludeTotals(true), management.Page(page))
		if err != nil {
			return nil, fmt.Errorf("could not list roles: %w", err)
		}

		for _, role := range listRes.Roles {
			roles = append(roles, &directory.Group{
				Id:   *role.ID,
				Name: *role.Name,
			})
		}

		page++
		shouldContinue = listRes.HasNext()
	}

	return roles, nil
}

func getRoleUserIDs(rm RoleManager, id string) ([]string, error) {
	var ids []string

	shouldContinue := true
	page := 0

	for shouldContinue {
		usersRes, err := rm.Users(id, management.IncludeTotals(true), management.Page(page))
		if err != nil {
			return nil, fmt.Errorf("could not get users for role %q: %w", id, err)
		}

		for _, user := range usersRes.Users {
			ids = append(ids, *user.ID)
		}

		page++
		shouldContinue = usersRes.HasNext()
	}

	return ids, nil
}

// A ServiceAccount is used by the Auth0 provider to query the API.
type ServiceAccount struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
}

// ParseServiceAccount parses the service account in the config options.
func ParseServiceAccount(rawServiceAccount string) (*ServiceAccount, error) {
	bs, err := base64.StdEncoding.DecodeString(rawServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("auth0: could not decode base64: %w", err)
	}

	var serviceAccount ServiceAccount
	if err := json.Unmarshal(bs, &serviceAccount); err != nil {
		return nil, fmt.Errorf("auth0: could not unmarshal json: %w", err)
	}

	if serviceAccount.ClientID == "" {
		return nil, errors.New("auth0: client_id is required")
	}

	if serviceAccount.Secret == "" {
		return nil, errors.New("auth0: secret is required")
	}

	return &serviceAccount, nil
}
