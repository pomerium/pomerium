// Package ping implements a directory provider for Ping.
package ping

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// Name is the name of the Ping provider.
const Name = "ping"

// Provider implements a directory provider using the Ping API.
type Provider struct {
	cfg   *config
	mu    sync.RWMutex
	token *oauth2.Token
}

// New creates a new Ping Provider.
func New(options ...Option) *Provider {
	cfg := getConfig(options...)
	return &Provider{
		cfg: cfg,
	}
}

// User returns a user's directory information.
func (p *Provider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	client, err := p.getClient(ctx)
	if err != nil {
		return nil, err
	}

	au, err := getUser(ctx, client, p.cfg.apiURL, p.cfg.environmentID, userID)
	if err != nil {
		return nil, err
	}

	return &directory.User{
		Id:          au.ID,
		DisplayName: au.getDisplayName(),
		Email:       au.Email,
		GroupIds:    au.MemberOfGroupIDs,
	}, nil
}

// UserGroups returns all the users and groups in the directory.
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	client, err := p.getClient(ctx)
	if err != nil {
		return nil, nil, err
	}

	apiGroups, err := getAllGroups(ctx, client, p.cfg.apiURL, p.cfg.environmentID)
	if err != nil {
		return nil, nil, err
	}

	directoryUserLookup := map[string]*directory.User{}
	directoryGroups := make([]*directory.Group, len(apiGroups))
	for i, ag := range apiGroups {
		dg := &directory.Group{
			Id:   ag.ID,
			Name: ag.Name,
		}

		apiUsers, err := getGroupUsers(ctx, client, p.cfg.apiURL, p.cfg.environmentID, ag.ID)
		if err != nil {
			return nil, nil, err
		}
		for _, au := range apiUsers {
			du, ok := directoryUserLookup[au.ID]
			if !ok {
				du = &directory.User{
					Id:          au.ID,
					DisplayName: au.getDisplayName(),
					Email:       au.Email,
				}
				directoryUserLookup[au.ID] = du
			}
			du.GroupIds = append(du.GroupIds, ag.ID)
		}

		directoryGroups[i] = dg
	}
	sort.Slice(directoryGroups, func(i, j int) bool {
		return directoryGroups[i].Id < directoryGroups[j].Id
	})

	directoryUsers := make([]*directory.User, 0, len(directoryUserLookup))
	for _, du := range directoryUserLookup {
		directoryUsers = append(directoryUsers, du)
	}
	sort.Slice(directoryUsers, func(i, j int) bool {
		return directoryUsers[i].Id < directoryUsers[j].Id
	})

	return directoryGroups, directoryUsers, nil
}

func (p *Provider) getClient(ctx context.Context) (*http.Client, error) {
	token, err := p.getToken(ctx)
	if err != nil {
		return nil, err
	}

	client := new(http.Client)
	*client = *p.cfg.httpClient
	client.Transport = &oauth2.Transport{
		Source: oauth2.StaticTokenSource(token),
		Base:   p.cfg.httpClient.Transport,
	}
	return client, nil
}

func (p *Provider) getToken(ctx context.Context) (*oauth2.Token, error) {
	if p.cfg.serviceAccount == nil {
		return nil, fmt.Errorf("ping: service account is required")
	}
	environmentID := p.cfg.serviceAccount.EnvironmentID
	if environmentID == "" {
		environmentID = p.cfg.environmentID
	}
	if environmentID == "" {
		return nil, fmt.Errorf("ping: environment ID is required")
	}

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

	ocfg := &clientcredentials.Config{
		ClientID:     p.cfg.serviceAccount.ClientID,
		ClientSecret: p.cfg.serviceAccount.ClientSecret,
		TokenURL: p.cfg.authURL.ResolveReference(&url.URL{
			Path: fmt.Sprintf("/%s/as/token", environmentID),
		}).String(),
	}
	var err error
	p.token, err = ocfg.Token(ctx)
	if err != nil {
		return nil, err
	}

	return p.token, nil
}
