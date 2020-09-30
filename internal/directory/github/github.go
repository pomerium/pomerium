// Package github contains a directory provider for github.
package github

import (
	"bytes"
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

// User returns the user record for the given id.
func (p *Provider) User(ctx context.Context, userID string) (*directory.User, error) {
	if p.cfg.serviceAccount == nil {
		return nil, fmt.Errorf("github: service account not defined")
	}

	_, providerUserID := databroker.FromUserID(userID)
	du := &directory.User{
		Id: userID,
	}

	au, err := p.getUser(ctx, providerUserID)
	if err != nil {
		return nil, err
	}
	du.DisplayName = au.Name
	du.Email = au.Email

	teamIDLookup := map[int]struct{}{}
	orgSlugs, err := p.listOrgs(ctx)
	if err != nil {
		return nil, err
	}
	for _, orgSlug := range orgSlugs {
		teamIDs, err := p.listUserOrganizationTeams(ctx, userID, orgSlug)
		if err != nil {
			return nil, err
		}
		for _, teamID := range teamIDs {
			teamIDLookup[teamID] = struct{}{}
		}
	}

	for teamID := range teamIDLookup {
		du.GroupIds = append(du.GroupIds, strconv.Itoa(teamID))
	}
	sort.Strings(du.GroupIds)

	return du, nil
}

// UserGroups gets the directory user groups for github.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	if p.cfg.serviceAccount == nil {
		return nil, nil, fmt.Errorf("github: service account not defined")
	}

	orgSlugs, err := p.listOrgs(ctx)
	if err != nil {
		return nil, nil, err
	}

	userLoginToGroups := map[string][]string{}

	var allGroups []*directory.Group
	for _, orgSlug := range orgSlugs {
		groups, err := p.listGroups(ctx, orgSlug)
		if err != nil {
			return nil, nil, err
		}

		for _, group := range groups {
			userLogins, err := p.listTeamMembers(ctx, orgSlug, group.Name)
			if err != nil {
				return nil, nil, err
			}

			for _, userLogin := range userLogins {
				userLoginToGroups[userLogin] = append(userLoginToGroups[userLogin], group.Id)
			}
		}

		allGroups = append(allGroups, groups...)
	}

	var users []*directory.User
	for userLogin, groups := range userLoginToGroups {
		u, err := p.getUser(ctx, userLogin)
		if err != nil {
			return nil, nil, err
		}

		user := &directory.User{
			Id:          databroker.GetUserID(Name, userLogin),
			GroupIds:    groups,
			DisplayName: u.Name,
			Email:       u.Email,
		}
		sort.Strings(user.GroupIds)
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].GetId() < users[j].GetId()
	})
	return allGroups, users, nil
}

func (p *Provider) listOrgs(ctx context.Context) (orgSlugs []string, err error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: "/user/orgs",
	}).String()

	for nextURL != "" {
		var results []struct {
			Login string `json:"login"`
		}
		hdrs, err := p.api(ctx, nextURL, &results)
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

func (p *Provider) listGroups(ctx context.Context, orgSlug string) ([]*directory.Group, error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/orgs/%s/teams", orgSlug),
	}).String()

	var groups []*directory.Group
	for nextURL != "" {
		var results []struct {
			ID   int    `json:"id"`
			Slug string `json:"slug"`
		}
		hdrs, err := p.api(ctx, nextURL, &results)
		if err != nil {
			return nil, err
		}

		for _, result := range results {
			groups = append(groups, &directory.Group{
				Id:   strconv.Itoa(result.ID),
				Name: result.Slug,
			})
		}

		nextURL = getNextLink(hdrs)
	}

	return groups, nil
}

func (p *Provider) listTeamMembers(ctx context.Context, orgSlug, teamSlug string) (userLogins []string, err error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/orgs/%s/teams/%s/members", orgSlug, teamSlug),
	}).String()

	for nextURL != "" {
		var results []struct {
			Login string `json:"login"`
		}
		hdrs, err := p.api(ctx, nextURL, &results)
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

func (p *Provider) getUser(ctx context.Context, userLogin string) (*apiUserObject, error) {
	apiURL := p.cfg.url.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/users/%s", userLogin),
	}).String()

	var res apiUserObject
	_, err := p.api(ctx, apiURL, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (p *Provider) listUserOrganizationTeams(ctx context.Context, userSlug string, orgSlug string) ([]int, error) {
	// GitHub's Rest API doesn't have an easy way of querying this data, so we use the GraphQL API.

	enc := func(obj interface{}) string {
		bs, _ := json.Marshal(obj)
		return string(bs)
	}
	const pageCount = 100

	var teamIDs []int
	var cursor *string
	for {
		var res struct {
			Data struct {
				Organization struct {
					Teams struct {
						TotalCount int `json:"totalCount"`
						PageInfo   struct {
							EndCursor string `json:"endCursor"`
						} `json:"pageInfo"`
						Edges []struct {
							Node struct {
								ID int `json:"id"`
							} `json:"node"`
						} `json:"edges"`
					} `json:"teams"`
				} `json:"organization"`
			} `json:"data"`
		}
		cursorStr := ""
		if cursor != nil {
			cursorStr = fmt.Sprintf(",%s", enc(*cursor))
		}
		q := fmt.Sprintf(`query {
			organization(login:%s) {
				teams(first:%s, userLogins:[%s] %s) {
					totalCount
					pageInfo {
						endCursor
					}
					edges {
						node {
							id
						}
					}
				}
			}
		}`, enc(orgSlug), enc(pageCount), enc(userSlug), cursorStr)
		_, err := p.graphql(ctx, q, &res)
		if err != nil {
			return nil, err
		}

		if len(res.Data.Organization.Teams.Edges) == 0 {
			break
		}

		for _, edge := range res.Data.Organization.Teams.Edges {
			teamIDs = append(teamIDs, edge.Node.ID)
		}

		if len(teamIDs) >= res.Data.Organization.Teams.TotalCount {
			break
		}

		cursor = &res.Data.Organization.Teams.PageInfo.EndCursor
	}

	return teamIDs, nil
}

func (p *Provider) api(ctx context.Context, apiURL string, out interface{}) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
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

func (p *Provider) graphql(ctx context.Context, query string, out interface{}) (http.Header, error) {
	apiURL := p.cfg.url.ResolveReference(&url.URL{
		Path: "/graphql",
	}).String()

	bs, _ := json.Marshal(struct {
		Query string `json:"query"`
	}{query})

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(bs))
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

// see: https://docs.github.com/en/free-pro-team@latest/rest/reference/users#get-a-user
type apiUserObject struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}
