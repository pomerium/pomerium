// Package gitlab contains a directory provider for gitlab.
package gitlab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/tomnomnom/linkheader"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// Name is the provider name.
const Name = "gitlab"

var (
	defaultURL = &url.URL{
		Scheme: "https",
		Host:   "gitlab.com",
	}
)

type config struct {
	httpClient     *http.Client
	serviceAccount *ServiceAccount
	url            *url.URL
}

// An Option updates the gitlab configuration.
type Option func(cfg *config)

// WithServiceAccount sets the service account in the config.
func WithServiceAccount(serviceAccount *ServiceAccount) Option {
	return func(cfg *config) {
		cfg.serviceAccount = serviceAccount
	}
}

// WithHTTPClient sets the http client option.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *config) {
		cfg.httpClient = httpClient
	}
}

// WithURL sets the api url in the config.
func WithURL(u *url.URL) Option {
	return func(cfg *config) {
		cfg.url = u
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithHTTPClient(http.DefaultClient)(cfg)
	WithURL(defaultURL)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// The Provider retrieves users and groups from gitlab.
type Provider struct {
	cfg *config
	log zerolog.Logger
}

// New creates a new Provider.
func New(options ...Option) *Provider {
	return &Provider{
		cfg: getConfig(options...),
		log: log.With().Str("service", "directory").Str("provider", "gitlab").Logger(),
	}
}

// User returns the user record for the given id.
func (p *Provider) User(ctx context.Context, id string) (*directory.User, error) {
	panic("not implemented")
}

// UserGroups gets the directory user groups for gitlab.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	if p.cfg.serviceAccount == nil {
		return nil, nil, fmt.Errorf("gitlab: service account not defined")
	}

	p.log.Info().Msg("getting user groups")

	groups, err := p.listGroups(ctx)
	if err != nil {
		return nil, nil, err
	}

	userLookup := map[int]apiUserObject{}
	userIDToGroupIDs := map[int][]string{}
	for _, group := range groups {
		users, err := p.listGroupMembers(ctx, group.Id)
		if err != nil {
			return nil, nil, err
		}

		for _, u := range users {
			userIDToGroupIDs[u.ID] = append(userIDToGroupIDs[u.ID], group.Id)
			userLookup[u.ID] = u
		}
	}

	var users []*directory.User
	for _, u := range userLookup {
		user := &directory.User{
			Id:          databroker.GetUserID(Name, fmt.Sprint(u.ID)),
			DisplayName: u.Name,
			Email:       u.Email,
		}

		user.GroupIds = append(user.GroupIds, userIDToGroupIDs[u.ID]...)

		sort.Strings(user.GroupIds)
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].GetId() < users[j].GetId()
	})
	return groups, users, nil
}

// listGroups returns a map, with key is group ID, element is group name.
func (p *Provider) listGroups(ctx context.Context) ([]*directory.Group, error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: "/api/v4/groups",
	}).String()
	var groups []*directory.Group
	for nextURL != "" {
		var result []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		}
		hdrs, err := p.apiGet(ctx, nextURL, &result)
		if err != nil {
			return nil, fmt.Errorf("gitlab: error querying groups: %w", err)
		}

		for _, r := range result {
			groups = append(groups, &directory.Group{
				Id:   strconv.Itoa(r.ID),
				Name: r.Name,
			})
		}

		nextURL = getNextLink(hdrs)
	}
	return groups, nil
}

func (p *Provider) listGroupMembers(ctx context.Context, groupID string) (users []apiUserObject, err error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/api/v4/groups/%s/members", groupID),
	}).String()
	for nextURL != "" {
		var result []apiUserObject
		hdrs, err := p.apiGet(ctx, nextURL, &result)
		if err != nil {
			return nil, fmt.Errorf("gitlab: error querying group members: %w", err)
		}

		users = append(users, result...)
		nextURL = getNextLink(hdrs)
	}
	return users, nil
}

func (p *Provider) apiGet(ctx context.Context, uri string, out interface{}) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("gitlab: failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PRIVATE-TOKEN", p.cfg.serviceAccount.PrivateToken)

	res, err := p.cfg.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("gitlab: error query api status_code=%d: %s", res.StatusCode, res.Status)
	}

	err = json.NewDecoder(res.Body).Decode(out)
	if err != nil {
		return nil, err
	}

	return res.Header, nil
}

func getNextLink(hdrs http.Header) string {
	for _, link := range linkheader.ParseMultiple(hdrs.Values("Link")) {
		if link.Rel == "next" {
			return link.URL
		}
	}
	return ""
}

// A ServiceAccount is used by the Gitlab provider to query the Gitlab API.
type ServiceAccount struct {
	PrivateToken string `json:"private_token"`
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

	if serviceAccount.PrivateToken == "" {
		return nil, fmt.Errorf("private_token is required")
	}

	return &serviceAccount, nil
}

type apiUserObject struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}
