// Package google contains the Google directory provider.
package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"

	"github.com/pomerium/pomerium/internal/grpc/directory"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/log"
)

const (
	defaultProviderURL = "https://accounts.google.com"
)

// Required scopes for groups api
// https://developers.google.com/admin-sdk/directory/v1/reference/groups/list
var apiScopes = []string{admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope}

// A Provider is a Google directory provider.
type Provider struct {
	apiClient *admin.Service
}

// New creates a new Google directory provider.
func New(o *oauth.Options) (*Provider, error) {
	var p Provider
	var err error
	if o.ProviderURL == "" {
		o.ProviderURL = defaultProviderURL
	}
	if o.ServiceAccount == "" {
		log.Warn().Msg("google: no service account, will not fetch groups")
		return &p, nil
	}

	apiCreds, err := base64.StdEncoding.DecodeString(o.ServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("google: could not decode service account json %w", err)
	}
	conf, err := google.JWTConfigFromJSON(apiCreds, apiScopes...)
	if err != nil {
		return nil, fmt.Errorf("google: failed making jwt config from json %w", err)
	}
	var credentialsFile struct {
		ImpersonateUser string `json:"impersonate_user"`
	}
	if err := json.Unmarshal(apiCreds, &credentialsFile); err != nil {
		return nil, err
	}
	conf.Subject = credentialsFile.ImpersonateUser
	client := conf.Client(context.TODO())
	p.apiClient, err = admin.NewService(context.TODO(), option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("google: failed creating admin service %w", err)
	}

	return &p, nil
}

// UserGroups returns a slice of group names a given user is in
// NOTE: groups via Directory API is limited to 1 QPS!
// https://developers.google.com/admin-sdk/directory/v1/reference/groups/list
// https://developers.google.com/admin-sdk/directory/v1/limits
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.User, error) {
	if p.apiClient == nil {
		return nil, errors.New("google: trying to fetch groups, but no api client")
	}

	var groups []string
	err := p.apiClient.Groups.List().
		Context(ctx).
		Pages(ctx, func(res *admin.Groups) error {
			for _, g := range res.Groups {
				groups = append(groups, g.Id)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}

	userEmailToGroups := map[string][]string{}
	for _, group := range groups {
		group := group
		err := p.apiClient.Members.List(group).
			Context(ctx).
			Pages(ctx, func(res *admin.Members) error {
				for _, member := range res.Members {
					userEmailToGroups[member.Email] = append(userEmailToGroups[member.Email], group)
				}
				return nil
			})
		if err != nil {
			return nil, err
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
