// Package onelogin contains the onelogin directory provider.
package onelogin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/grpc/directory"
	"github.com/pomerium/pomerium/internal/log"
)

type config struct {
	apiURL         *url.URL
	batchSize      int
	serviceAccount *ServiceAccount
	httpClient     *http.Client
}

// An Option updates the onelogin configuration.
type Option func(*config)

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

// WithServiceAccount sets the service account in the config.
func WithServiceAccount(serviceAccount *ServiceAccount) Option {
	return func(cfg *config) {
		cfg.serviceAccount = serviceAccount
	}
}

// WithURL sets the api url in the config.
func WithURL(apiURL *url.URL) Option {
	return func(cfg *config) {
		cfg.apiURL = apiURL
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithBatchSize(20)(cfg)
	WithHTTPClient(http.DefaultClient)(cfg)
	WithURL(&url.URL{
		Scheme: "https",
		Host:   "api.us.onelogin.com",
	})(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// The Provider retrieves users and groups from onelogin.
type Provider struct {
	cfg *config
	log zerolog.Logger

	mu    sync.RWMutex
	token *oauth2.Token
}

// New creates a new Provider.
func New(options ...Option) *Provider {
	cfg := getConfig(options...)
	return &Provider{
		cfg: cfg,
		log: log.With().Str("service", "directory").Str("provider", "onelogin").Logger(),
	}
}

// UserGroups gets the directory user groups for onelogin.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.User, error) {
	if p.cfg.serviceAccount == nil {
		return nil, fmt.Errorf("onelogin: service account not defined")
	}

	p.log.Info().Msg("getting user groups")

	token, err := p.getToken(ctx)
	if err != nil {
		return nil, err
	}

	groupIDToName, err := p.getGroupIDToName(ctx, token)
	if err != nil {
		return nil, err
	}

	userEmailToGroupIDs, err := p.getUserEmailToGroupIDs(ctx, token)
	if err != nil {
		return nil, err
	}

	userEmailToGroupNames := map[string][]string{}
	for email, groupIDs := range userEmailToGroupIDs {
		for _, groupID := range groupIDs {
			if groupName, ok := groupIDToName[groupID]; ok {
				userEmailToGroupNames[email] = append(userEmailToGroupNames[email], groupName)
			} else {
				userEmailToGroupNames[email] = append(userEmailToGroupNames[email], "NOGROUP")
			}
		}
	}

	var users []*directory.User
	for userEmail, groups := range userEmailToGroupNames {
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

func (p *Provider) getGroupIDToName(ctx context.Context, token *oauth2.Token) (map[int]string, error) {
	groupIDToName := map[int]string{}

	apiURL := p.cfg.apiURL.ResolveReference(&url.URL{
		Path:     "/api/1/groups",
		RawQuery: fmt.Sprintf("limit=%d", p.cfg.batchSize),
	}).String()
	for apiURL != "" {
		var result []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		}
		nextLink, err := p.apiGet(ctx, token, apiURL, &result)
		if err != nil {
			return nil, fmt.Errorf("onelogin: error querying group api: %w", err)
		}

		for _, r := range result {
			groupIDToName[r.ID] = r.Name
		}

		apiURL = nextLink
	}

	return groupIDToName, nil
}

func (p *Provider) getUserEmailToGroupIDs(ctx context.Context, token *oauth2.Token) (map[string][]int, error) {
	userEmailToGroupIDs := map[string][]int{}

	apiURL := p.cfg.apiURL.ResolveReference(&url.URL{
		Path:     "/api/1/users",
		RawQuery: fmt.Sprintf("limit=%d", p.cfg.batchSize),
	}).String()
	for apiURL != "" {
		var result []struct {
			Email   string `json:"email"`
			GroupID *int   `json:"group_id"`
		}
		nextLink, err := p.apiGet(ctx, token, apiURL, &result)
		if err != nil {
			return nil, err
		}

		for _, r := range result {
			groupID := 0
			if r.GroupID != nil {
				groupID = *r.GroupID
			}
			userEmailToGroupIDs[r.Email] = append(userEmailToGroupIDs[r.Email], groupID)
		}

		apiURL = nextLink
	}

	return userEmailToGroupIDs, nil
}

func (p *Provider) apiGet(ctx context.Context, token *oauth2.Token, uri string, out interface{}) (nextLink string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("bearer:%s", token.AccessToken))
	req.Header.Set("Content-Type", "application/json")

	res, err := p.cfg.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return "", fmt.Errorf("onelogin: error querying api: %s", res.Status)
	}

	var result struct {
		Pagination struct {
			NextLink string `json:"next_link"`
		}
		Data json.RawMessage `json:"data"`
	}
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	p.log.Info().
		Str("url", uri).
		Interface("result", result).
		Msg("api request")

	err = json.Unmarshal(result.Data, out)
	if err != nil {
		return "", err
	}

	return result.Pagination.NextLink, nil
}

func (p *Provider) getToken(ctx context.Context) (*oauth2.Token, error) {
	p.mu.RLock()
	token := p.token
	p.mu.RUnlock()

	if token != nil && token.Valid() {
		return token, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	token = p.token
	if token != nil && token.Valid() {
		return token, nil
	}

	apiURL := p.cfg.apiURL.ResolveReference(&url.URL{
		Path: "/auth/oauth2/v2/token",
	})

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL.String(), strings.NewReader(`{ "grant_type": "client_credentials" }`))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("client_id:%s, client_secret:%s",
		p.cfg.serviceAccount.ClientID, p.cfg.serviceAccount.ClientSecret))
	req.Header.Set("Content-Type", "application/json")

	res, err := p.cfg.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("onelogin: error querying oauth2 token: %s", res.Status)
	}
	err = json.NewDecoder(res.Body).Decode(&token)
	if err != nil {
		return nil, err
	}
	p.token = token

	return p.token, nil
}

// A ServiceAccount is used by the OneLogin provider to query the API.
type ServiceAccount struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
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

	if serviceAccount.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if serviceAccount.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}

	return &serviceAccount, nil
}
