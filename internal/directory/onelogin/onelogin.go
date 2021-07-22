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
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// Name is the provider name.
const Name = "onelogin"

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
		cfg.httpClient = httputil.NewLoggingClient(httpClient,
			func(evt *zerolog.Event) *zerolog.Event {
				return evt.Str("provider", "onelogin")
			})
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

	mu    sync.RWMutex
	token *oauth2.Token
}

// New creates a new Provider.
func New(options ...Option) *Provider {
	cfg := getConfig(options...)
	return &Provider{
		cfg: cfg,
	}
}

func withLog(ctx context.Context) context.Context {
	return log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "directory").Str("provider", "onelogin")
	})
}

// User returns the user record for the given id.
func (p *Provider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	if p.cfg.serviceAccount == nil {
		return nil, fmt.Errorf("onelogin: service account not defined")
	}
	du := &directory.User{
		Id: userID,
	}

	ctx = withLog(ctx)

	token, err := p.getToken(ctx)
	if err != nil {
		return nil, err
	}

	au, err := p.getUser(ctx, token.AccessToken, userID)
	if err != nil {
		return nil, err
	}
	du.DisplayName = au.getDisplayName()
	du.Email = au.Email
	du.GroupIds = []string{strconv.Itoa(au.GroupID)}

	return du, nil
}

// UserGroups gets the directory user groups for onelogin.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	if p.cfg.serviceAccount == nil {
		return nil, nil, fmt.Errorf("onelogin: service account not defined")
	}

	ctx = withLog(ctx)

	log.Info(ctx).Msg("getting user groups")

	token, err := p.getToken(ctx)
	if err != nil {
		return nil, nil, err
	}

	groups, err := p.listGroups(ctx, token.AccessToken)
	if err != nil {
		return nil, nil, err
	}

	apiUsers, err := p.listUsers(ctx, token.AccessToken)
	if err != nil {
		return nil, nil, err
	}

	var users []*directory.User
	for _, u := range apiUsers {
		users = append(users, &directory.User{
			Id:          strconv.Itoa(u.ID),
			GroupIds:    []string{strconv.Itoa(u.GroupID)},
			DisplayName: u.FirstName + " " + u.LastName,
			Email:       u.Email,
		})
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Id < users[j].Id
	})
	return groups, users, nil
}

func (p *Provider) listGroups(ctx context.Context, accessToken string) ([]*directory.Group, error) {
	var groups []*directory.Group
	apiURL := p.cfg.apiURL.ResolveReference(&url.URL{
		Path:     "/api/1/groups",
		RawQuery: fmt.Sprintf("limit=%d", p.cfg.batchSize),
	}).String()
	for apiURL != "" {
		var result []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		}
		nextLink, err := p.apiGet(ctx, accessToken, apiURL, &result)
		if err != nil {
			return nil, fmt.Errorf("onelogin: listing groups: %w", err)
		}

		for _, r := range result {
			groups = append(groups, &directory.Group{
				Id:   strconv.Itoa(r.ID),
				Name: r.Name,
			})
		}

		apiURL = nextLink
	}
	return groups, nil
}

func (p *Provider) getUser(ctx context.Context, accessToken string, userID string) (*apiUserObject, error) {
	apiURL := p.cfg.apiURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/api/1/users/%s", userID),
	}).String()

	var out []apiUserObject
	_, err := p.apiGet(ctx, accessToken, apiURL, &out)
	if err != nil {
		return nil, fmt.Errorf("onelogin: error getting user: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("onelogin: user not found")
	}

	return &out[0], nil
}

func (p *Provider) listUsers(ctx context.Context, accessToken string) ([]apiUserObject, error) {
	var users []apiUserObject

	apiURL := p.cfg.apiURL.ResolveReference(&url.URL{
		Path:     "/api/1/users",
		RawQuery: fmt.Sprintf("limit=%d", p.cfg.batchSize),
	}).String()
	for apiURL != "" {
		var result []apiUserObject
		nextLink, err := p.apiGet(ctx, accessToken, apiURL, &result)
		if err != nil {
			return nil, fmt.Errorf("onelogin: listing users: %w", err)
		}

		users = append(users, result...)
		apiURL = nextLink
	}

	return users, nil
}

func (p *Provider) apiGet(ctx context.Context, accessToken string, uri string, out interface{}) (nextLink string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("bearer:%s", accessToken))
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

	log.Info(ctx).
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

type apiUserObject struct {
	ID        int    `json:"id"`
	GroupID   int    `json:"group_id"`
	Email     string `json:"email"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

func (obj *apiUserObject) getDisplayName() string {
	return obj.FirstName + " " + obj.LastName
}
