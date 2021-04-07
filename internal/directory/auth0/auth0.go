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
	"gopkg.in/auth0.v5/management"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// Name is the provider name.
const Name = "auth0"

type (
	// RoleManager defines what is needed to get role info from Auth0.
	RoleManager interface {
		List(opts ...management.RequestOption) (r *management.RoleList, err error)
		Users(id string, opts ...management.RequestOption) (u *management.UserList, err error)
	}
	// UserManager defines what is needed to get user info from Auth0.
	UserManager interface {
		Read(id string, opts ...management.RequestOption) (*management.User, error)
		Roles(id string, opts ...management.RequestOption) (r *management.RoleList, err error)
	}
)

type newManagersFunc = func(ctx context.Context, domain string, serviceAccount *ServiceAccount) (RoleManager, UserManager, error)

func defaultNewManagersFunc(ctx context.Context, domain string, serviceAccount *ServiceAccount) (RoleManager, UserManager, error) {
	m, err := management.New(domain,
		management.WithClientCredentials(serviceAccount.ClientID, serviceAccount.Secret),
		management.WithContext(ctx))
	if err != nil {
		return nil, nil, fmt.Errorf("auth0: could not build management: %w", err)
	}
	return m.Role, m.User, nil
}

type config struct {
	domain         string
	serviceAccount *ServiceAccount
	newManagers    newManagersFunc
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

func getConfig(options ...Option) *config {
	cfg := &config{
		newManagers: defaultNewManagersFunc,
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

func (p *Provider) getManagers(ctx context.Context) (RoleManager, UserManager, error) {
	return p.cfg.newManagers(ctx, p.cfg.domain, p.cfg.serviceAccount)
}

// User returns the user record for the given id.
func (p *Provider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	_, um, err := p.getManagers(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth0: could not get the role manager: %w", err)
	}

	du := &directory.User{
		Id: userID,
	}

	u, err := um.Read(userID)
	if err != nil {
		return nil, fmt.Errorf("auth0: error getting user info: %w", err)
	}
	du.DisplayName = u.GetName()
	du.Email = u.GetEmail()

	for page, hasNext := 0, true; hasNext; page++ {
		rl, err := um.Roles(userID, management.IncludeTotals(true), management.Page(page))
		if err != nil {
			return nil, fmt.Errorf("auth0: error getting user roles: %w", err)
		}

		for _, role := range rl.Roles {
			du.GroupIds = append(du.GroupIds, role.GetID())
		}

		hasNext = rl.HasNext()
	}

	sort.Strings(du.GroupIds)
	return du, nil
}

// UserGroups fetches a slice of groups and users.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	rm, _, err := p.getManagers(ctx)
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
			Id:       userID,
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

	sort.Slice(roles, func(i, j int) bool {
		return roles[i].GetId() < roles[j].GetId()
	})
	return roles, nil
}

func getRoleUserIDs(rm RoleManager, roleID string) ([]string, error) {
	var ids []string

	shouldContinue := true
	page := 0

	for shouldContinue {
		usersRes, err := rm.Users(roleID, management.IncludeTotals(true), management.Page(page))
		if err != nil {
			return nil, fmt.Errorf("could not get users for role %q: %w", roleID, err)
		}

		for _, user := range usersRes.Users {
			ids = append(ids, *user.ID)
		}

		page++
		shouldContinue = usersRes.HasNext()
	}

	sort.Strings(ids)
	return ids, nil
}

// A ServiceAccount is used by the Auth0 provider to query the API.
type ServiceAccount struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
}

// ParseServiceAccount parses the service account in the config options.
func ParseServiceAccount(options directory.Options) (*ServiceAccount, error) {
	if options.ServiceAccount != "" {
		return parseServiceAccountFromString(options.ServiceAccount)
	}
	return parseServiceAccountFromOptions(options.ClientID, options.ClientSecret)
}

func parseServiceAccountFromOptions(clientID, clientSecret string) (*ServiceAccount, error) {
	serviceAccount := ServiceAccount{
		ClientID: clientID,
		Secret:   clientSecret,
	}

	if serviceAccount.ClientID == "" {
		return nil, fmt.Errorf("auth0: client_id is required")
	}
	if serviceAccount.Secret == "" {
		return nil, fmt.Errorf("auth0: client_secret is required")
	}

	return &serviceAccount, nil
}

func parseServiceAccountFromString(rawServiceAccount string) (*ServiceAccount, error) {
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
