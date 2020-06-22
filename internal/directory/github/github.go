// Package github contains a directory provider for github.
package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"

	"github.com/rs/zerolog"
	"github.com/tomnomnom/linkheader"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/grpc/directory"
	"github.com/pomerium/pomerium/internal/log"
)

// Name is the provider name.
const Name = "github"

var (
	defaultURL = &url.URL{
		Scheme: "https",
		Host:   "api.github.com",
	}
)

type config struct {
	httpClient     *http.Client
	serviceAccount *ServiceAccount
	url            *url.URL
}

// An Option updates the github configuration.
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

// The Provider retrieves users and groups from github.
type Provider struct {
	cfg *config
	log zerolog.Logger
}

// New creates a new Provider.
func New(options ...Option) *Provider {
	return &Provider{
		cfg: getConfig(options...),
		log: log.With().Str("service", "directory").Str("provider", "github").Logger(),
	}
}

// UserGroups gets the directory user groups for github.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.User, error) {
	if p.cfg.serviceAccount == nil {
		return nil, fmt.Errorf("github: service account not defined")
	}

	orgSlugs, err := p.listOrgs(ctx)
	if err != nil {
		return nil, err
	}

	userLoginToGroups := map[string][]string{}

	for _, orgSlug := range orgSlugs {
		teamSlugs, err := p.listTeams(ctx, orgSlug)
		if err != nil {
			return nil, err
		}

		for _, teamSlug := range teamSlugs {
			userLogins, err := p.listTeamMembers(ctx, orgSlug, teamSlug)
			if err != nil {
				return nil, err
			}

			for _, userLogin := range userLogins {
				userLoginToGroups[userLogin] = append(userLoginToGroups[userLogin], teamSlug)
			}
		}
	}

	var users []*directory.User
	for userLogin, groups := range userLoginToGroups {
		user := &directory.User{
			Id:     databroker.GetUserID(Name, userLogin),
			Groups: groups,
		}
		sort.Strings(user.Groups)
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].GetId() < users[j].GetId()
	})
	return users, nil
}

func (p *Provider) listOrgs(ctx context.Context) (orgSlugs []string, err error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: "/user/orgs",
	}).String()

	for nextURL != "" {
		var results []struct {
			Login string `json:"login"`
		}
		hdrs, err := p.api(ctx, "GET", nextURL, nil, &results)
		if err != nil {
			return nil, err
		}

		for _, result := range results {
			orgSlugs = append(orgSlugs, result.Login)
		}

		nextURL = getNextLink(hdrs)
	}

	return orgSlugs, nil
}

func (p *Provider) listTeams(ctx context.Context, orgSlug string) (teamSlugs []string, err error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/orgs/%s/teams", orgSlug),
	}).String()

	for nextURL != "" {
		var results []struct {
			Slug string `json:"slug"`
		}
		hdrs, err := p.api(ctx, "GET", nextURL, nil, &results)
		if err != nil {
			return nil, err
		}

		for _, result := range results {
			teamSlugs = append(teamSlugs, result.Slug)
		}

		nextURL = getNextLink(hdrs)
	}

	return teamSlugs, nil
}

func (p *Provider) listTeamMembers(ctx context.Context, orgSlug, teamSlug string) (userLogins []string, err error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/orgs/%s/teams/%s/members", orgSlug, teamSlug),
	}).String()

	for nextURL != "" {
		var results []struct {
			ID    int    `json:"id"`
			Login string `json:"login"`
		}
		hdrs, err := p.api(ctx, "GET", nextURL, nil, &results)
		if err != nil {
			return nil, err
		}

		for _, result := range results {
			userLogins = append(userLogins, result.Login)
		}

		nextURL = getNextLink(hdrs)
	}

	return userLogins, err
}

func (p *Provider) api(ctx context.Context, method string, apiURL string, in, out interface{}) (http.Header, error) {
	var body io.Reader
	if in != nil {
		bs, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("github: failed to marshal api input")
		}
		body = bytes.NewReader(bs)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiURL, body)
	if err != nil {
		return nil, fmt.Errorf("github: failed to create http request: %w", err)
	}
	req.SetBasicAuth(p.cfg.serviceAccount.Username, p.cfg.serviceAccount.PersonalAccessToken)

	res, err := p.cfg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: failed to make http request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("github: error from API: %s", res.Status)
	}

	if out != nil {
		err := json.NewDecoder(res.Body).Decode(out)
		if err != nil {
			return nil, fmt.Errorf("github: failed to decode json body: %w", err)
		}
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

// A ServiceAccount is used by the GitHub provider to query the GitHub API.
type ServiceAccount struct {
	Username            string `json:"username"`
	PersonalAccessToken string `json:"personal_access_token"`
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

	if serviceAccount.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if serviceAccount.PersonalAccessToken == "" {
		return nil, fmt.Errorf("personal_access_token is required")
	}

	return &serviceAccount, nil
}
