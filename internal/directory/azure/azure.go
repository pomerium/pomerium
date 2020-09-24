// Package azure contains an azure active directory directory provider.
package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// Name is the provider name.
const Name = "azure"

const (
	defaultGraphHost = "graph.microsoft.com"

	defaultLoginHost      = "login.microsoftonline.com"
	defaultLoginScope     = "https://graph.microsoft.com/.default"
	defaultLoginGrantType = "client_credentials"
)

type config struct {
	graphURL       *url.URL
	httpClient     *http.Client
	loginURL       *url.URL
	serviceAccount *ServiceAccount
}

// An Option updates the provider configuration.
type Option func(*config)

// WithGraphURL sets the graph URL for the configuration.
func WithGraphURL(graphURL *url.URL) Option {
	return func(cfg *config) {
		cfg.graphURL = graphURL
	}
}

// WithLoginURL sets the login URL for the configuration.
func WithLoginURL(loginURL *url.URL) Option {
	return func(cfg *config) {
		cfg.loginURL = loginURL
	}
}

// WithHTTPClient sets the http client to use for requests to the Azure APIs.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *config) {
		cfg.httpClient = httpClient
	}
}

// WithServiceAccount sets the service account to use to access Azure.
func WithServiceAccount(serviceAccount *ServiceAccount) Option {
	return func(cfg *config) {
		cfg.serviceAccount = serviceAccount
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithGraphURL(&url.URL{
		Scheme: "https",
		Host:   defaultGraphHost,
	})(cfg)
	WithHTTPClient(http.DefaultClient)(cfg)
	WithLoginURL(&url.URL{
		Scheme: "https",
		Host:   defaultLoginHost,
	})(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A Provider is a directory implementation using azure active directory.
type Provider struct {
	cfg *config
	gdc *groupsDeltaCollection

	mu    sync.RWMutex
	token *oauth2.Token
}

// New creates a new Provider.
func New(options ...Option) *Provider {
	p := &Provider{
		cfg: getConfig(options...),
	}
	p.gdc = newGroupsDeltaCollection(p)
	return p
}

// UserGroups returns the directory users in azure active directory.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	if p.cfg.serviceAccount == nil {
		return nil, nil, fmt.Errorf("azure: service account not defined")
	}

	err := p.gdc.Sync(ctx)
	if err != nil {
		return nil, nil, err
	}

	groups, users := p.gdc.CurrentUserGroups()
	return groups, users, nil
}

func (p *Provider) api(ctx context.Context, method, url string, body io.Reader, out interface{}) error {
	token, err := p.getToken(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("azure: error creating HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))

	res, err := p.cfg.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("azure: error making HTTP request: %w", err)
	}
	defer res.Body.Close()

	// if we get unauthorized, invalidate the token
	if res.StatusCode == http.StatusUnauthorized {
		p.mu.Lock()
		p.token = nil
		p.mu.Unlock()
	}

	if res.StatusCode/100 != 2 {
		return fmt.Errorf("azure: error querying api: %s", res.Status)
	}

	err = json.NewDecoder(res.Body).Decode(out)
	if err != nil {
		return fmt.Errorf("azure: error decoding api response: %w", err)
	}

	return nil
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

	tokenURL := p.cfg.loginURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/%s/oauth2/v2.0/token", p.cfg.serviceAccount.DirectoryID),
	})

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL.String(), strings.NewReader(url.Values{
		"client_id":     {p.cfg.serviceAccount.ClientID},
		"client_secret": {p.cfg.serviceAccount.ClientSecret},
		"scope":         {defaultLoginScope},
		"grant_type":    {defaultLoginGrantType},
	}.Encode()))
	if err != nil {
		return nil, fmt.Errorf("azure: error creating HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := p.cfg.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("azure: error querying oauth2 token: %s", res.Status)
	}
	err = json.NewDecoder(res.Body).Decode(&token)
	if err != nil {
		return nil, fmt.Errorf("azure: error decoding oauth2 token: %w", err)
	}
	p.token = token

	return p.token, nil
}

// A ServiceAccount is used by the Azure provider to query the Microsoft Graph API.
type ServiceAccount struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	DirectoryID  string `json:"directory_id"`
}

// ParseServiceAccount parses the service account in the config options.
func ParseServiceAccount(options directory.Options) (*ServiceAccount, error) {
	if options.ServiceAccount != "" {
		return parseServiceAccountFromString(options.ServiceAccount)
	}
	return parseServiceAccountFromOptions(options.ClientID, options.ClientSecret, options.ProviderURL)
}

func parseServiceAccountFromOptions(clientID, clientSecret, providerURL string) (*ServiceAccount, error) {
	serviceAccount := ServiceAccount{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	var err error
	serviceAccount.DirectoryID, err = parseDirectoryIDFromURL(providerURL)
	if err != nil {
		return nil, err
	}

	if serviceAccount.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if serviceAccount.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}
	if serviceAccount.DirectoryID == "" {
		return nil, fmt.Errorf("directory_id is required")
	}

	return &serviceAccount, nil
}

func parseServiceAccountFromString(rawServiceAccount string) (*ServiceAccount, error) {
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
	if serviceAccount.DirectoryID == "" {
		return nil, fmt.Errorf("directory_id is required")
	}

	return &serviceAccount, nil
}

func parseDirectoryIDFromURL(providerURL string) (string, error) {
	u, err := url.Parse(providerURL)
	if err != nil {
		return "", err
	}

	pathParts := strings.SplitN(u.Path, "/", 3)
	if len(pathParts) != 3 {
		return "", fmt.Errorf("no directory id found in path")
	}

	return pathParts[1], nil
}
