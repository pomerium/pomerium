// Package gitlab contains a directory provider for gitlab.
package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"

	"github.com/rs/zerolog"
	"github.com/tomnomnom/linkheader"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/log"
)

var (
	defaultURL = &url.URL{
		Scheme: "https",
		Host:   "gitlab.com",
	}
)

type config struct {
	url          *url.URL
	privateToken string
	httpClient   *http.Client
}

// An Option updates the gitlab configuration.
type Option func(cfg *config)

// WithPrivateToken sets the private token in the config.
func WithPrivateToken(privateToken string) Option {
	return func(cfg *config) {
		cfg.privateToken = privateToken
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

// UserGroups gets the directory user groups for gitlab.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.User, error) {
	p.log.Info().Msg("getting user groups")

	groupIDs, err := p.getGroups(ctx)
	if err != nil {
		return nil, err
	}

	userIDToGroupIDs := map[int][]int{}
	for _, groupID := range groupIDs {
		userIDs, err := p.getGroupMembers(ctx, groupID)
		if err != nil {
			return nil, err
		}

		for _, userID := range userIDs {
			userIDToGroupIDs[userID] = append(userIDToGroupIDs[userID], groupIDs...)
		}
	}

	var users []*directory.User
	for userID, groupIDs := range userIDToGroupIDs {
		user := &directory.User{
			Id: fmt.Sprint(userID),
		}
		for _, groupID := range groupIDs {
			user.Groups = append(user.Groups, fmt.Sprint(groupID))
		}
		sort.Strings(user.Groups)
		users = append(users, user)
	}
	return users, nil
}

func (p *Provider) getGroups(ctx context.Context) (groupIDs []int, err error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: "/groups",
	}).String()
	for nextURL != "" {
		var result []struct {
			ID int `json:"id"`
		}
		hdrs, err := p.apiGet(ctx, nextURL, &result)
		if err != nil {
			return nil, fmt.Errorf("gitlab: error querying groups: %w", err)
		}

		for _, r := range result {
			groupIDs = append(groupIDs, r.ID)
		}

		nextURL = getNextLink(hdrs)
	}
	return groupIDs, nil
}

func (p *Provider) getGroupMembers(ctx context.Context, groupID int) (userIDs []int, err error) {
	nextURL := p.cfg.url.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/groups/%d/members", groupID),
	}).String()
	for nextURL != "" {
		var result []struct {
			ID int `json:"id"`
		}
		hdrs, err := p.apiGet(ctx, nextURL, &result)
		if err != nil {
			return nil, fmt.Errorf("gitlab: error querying group members: %w", err)
		}

		for _, r := range result {
			userIDs = append(userIDs, r.ID)
		}

		nextURL = getNextLink(hdrs)
	}
	return userIDs, nil
}

func (p *Provider) apiGet(ctx context.Context, uri string, out interface{}) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("gitlab: failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PRIVATE-TOKEN", p.cfg.privateToken)

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
