// Package okta contains the Okta directory provider.
package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"

	"github.com/pomerium/pomerium/internal/directory"

	"github.com/tomnomnom/linkheader"
)

type config struct {
	apiToken    string
	httpClient  *http.Client
	providerURL *url.URL
	batchSize   int
}

// An Option configures the Okta Provider.
type Option func(cfg *config)

// WithAPIToken sets the api token option.
func WithAPIToken(apiToken string) Option {
	return func(cfg *config) {
		cfg.apiToken = apiToken
	}
}

// WithBatchSize sets the batch size option.
func WithBatchSize(batchSize int) Option {
	return func(cfg *config) {
		cfg.batchSize = batchSize
	}
}

// WithHTTPClient sets the http client option.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *config) {
		cfg.httpClient = httpClient
	}
}

// WithProviderURL sets the provider URL option.
func WithProviderURL(uri *url.URL) Option {
	return func(cfg *config) {
		cfg.providerURL = uri
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithBatchSize(100)(cfg)
	WithHTTPClient(http.DefaultClient)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A Provider is an Okta user group directory provider.
type Provider struct {
	cfg *config
}

// New creates a new Provider.
func New(options ...Option) *Provider {
	return &Provider{
		cfg: getConfig(options...),
	}
}

// UserGroups fetches the groups of which the user is a member
// https://developer.okta.com/docs/reference/api/users/#get-user-s-groups
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.User, error) {
	if p.cfg.apiToken == "" {
		return nil, fmt.Errorf("okta: api token not defined")
	}
	if p.cfg.providerURL == nil {
		return nil, fmt.Errorf("okta: provider url not defined")
	}

	groupIDToName, err := p.getGroups(ctx)
	if err != nil {
		return nil, err
	}

	userEmailToGroups := map[string][]string{}
	for groupID, groupName := range groupIDToName {
		emails, err := p.getGroupMemberEmails(ctx, groupID)
		if err != nil {
			return nil, err
		}
		for _, email := range emails {
			userEmailToGroups[email] = append(userEmailToGroups[email], groupName)
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

func (p *Provider) getGroups(ctx context.Context) (map[string]string, error) {
	groups := map[string]string{}

	groupURL := p.cfg.providerURL.ResolveReference(&url.URL{
		Path:     "/api/v1/groups",
		RawQuery: fmt.Sprintf("limit=%d", p.cfg.batchSize),
	}).String()
	for groupURL != "" {
		var out []struct {
			ID      string `json:"id"`
			Profile struct {
				Name string `json:"name"`
			} `json:"profile"`
		}
		hdrs, err := p.apiGet(ctx, groupURL, &out)
		if err != nil {
			return nil, fmt.Errorf("okta: error querying for groups: %w", err)
		}

		for _, el := range out {
			groups[el.ID] = el.Profile.Name
		}

		groupURL = getNextLink(hdrs)
	}

	return groups, nil
}

func (p *Provider) getGroupMemberEmails(ctx context.Context, groupID string) ([]string, error) {
	var emails []string

	usersURL := p.cfg.providerURL.ResolveReference(&url.URL{
		Path:     fmt.Sprintf("/api/v1/groups/%s/users", groupID),
		RawQuery: fmt.Sprintf("limit=%d", p.cfg.batchSize),
	}).String()
	for usersURL != "" {
		var out []struct {
			ID      string `json:"id"`
			Profile struct {
				Email string `json:"email"`
			} `json:"profile"`
		}
		hdrs, err := p.apiGet(ctx, usersURL, &out)
		if err != nil {
			return nil, fmt.Errorf("okta: error querying for groups: %w", err)
		}

		for _, el := range out {
			emails = append(emails, el.Profile.Email)
		}

		usersURL = getNextLink(hdrs)
	}

	return emails, nil
}

func (p *Provider) apiGet(ctx context.Context, uri string, out interface{}) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("okta: failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "SSWS "+p.cfg.apiToken)

	res, err := p.cfg.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("okta: error query api status_code=%d: %s", res.StatusCode, res.Status)
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
