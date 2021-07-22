// Package okta contains the Okta directory provider.
package okta

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/tomnomnom/linkheader"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

// Name is the provider name.
const Name = "okta"

const (
	// Okta use ISO-8601, see https://developer.okta.com/docs/reference/api-overview/#media-types
	filterDateFormat = "2006-01-02T15:04:05.999Z"

	batchSize        = 200
	readLimit        = 100 * 1024
	httpSuccessClass = 2
)

// Errors.
var (
	ErrAPIKeyRequired           = errors.New("okta: api_key is required")
	ErrServiceAccountNotDefined = errors.New("okta: service account not defined")
	ErrProviderURLNotDefined    = errors.New("okta: provider url not defined")
)

type config struct {
	batchSize      int
	httpClient     *http.Client
	providerURL    *url.URL
	serviceAccount *ServiceAccount
}

// An Option configures the Okta Provider.
type Option func(cfg *config)

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
				return evt.Str("provider", "okta")
			})
	}
}

// WithProviderURL sets the provider URL option.
func WithProviderURL(uri *url.URL) Option {
	return func(cfg *config) {
		cfg.providerURL = uri
	}
}

// WithServiceAccount sets the service account option.
func WithServiceAccount(serviceAccount *ServiceAccount) Option {
	return func(cfg *config) {
		cfg.serviceAccount = serviceAccount
	}
}

func getConfig(options ...Option) *config {
	cfg := new(config)
	WithBatchSize(batchSize)(cfg)
	WithHTTPClient(http.DefaultClient)(cfg)
	for _, option := range options {
		option(cfg)
	}

	return cfg
}

// A Provider is an Okta user group directory provider.
type Provider struct {
	cfg         *config
	lastUpdated *time.Time
	groups      map[string]*directory.Group
}

// New creates a new Provider.
func New(options ...Option) *Provider {
	return &Provider{
		cfg:    getConfig(options...),
		groups: make(map[string]*directory.Group),
	}
}

func withLog(ctx context.Context) context.Context {
	return log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "directory").Str("provider", "okta")
	})
}

// User returns the user record for the given id.
func (p *Provider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	ctx = withLog(ctx)

	if p.cfg.serviceAccount == nil {
		return nil, ErrServiceAccountNotDefined
	}

	du := &directory.User{
		Id: userID,
	}

	au, err := p.getUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	du.DisplayName = au.getDisplayName()
	du.Email = au.Profile.Email

	groups, err := p.listUserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		du.GroupIds = append(du.GroupIds, g.ID)
	}
	sort.Strings(du.GroupIds)

	return du, nil
}

// UserGroups fetches the groups of which the user is a member
// https://developer.okta.com/docs/reference/api/users/#get-user-s-groups
func (p *Provider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	ctx = withLog(ctx)

	if p.cfg.serviceAccount == nil {
		return nil, nil, ErrServiceAccountNotDefined
	}

	log.Info(ctx).Msg("getting user groups")

	if p.cfg.providerURL == nil {
		return nil, nil, ErrProviderURLNotDefined
	}

	groups, err := p.getGroups(ctx)
	if err != nil {
		return nil, nil, err
	}

	userLookup := map[string]apiUserObject{}
	userIDToGroups := map[string][]string{}
	for i := 0; i < len(groups); i++ {
		group := groups[i]
		users, err := p.getGroupMembers(ctx, group.Id)

		// if we get a 404 on the member query, it means the group doesn't exist, so we should remove it from
		// the cached lookup and the local groups list
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.HTTPStatusCode == http.StatusNotFound {
			log.Debug(ctx).Str("group", group.Id).Msg("okta: group was removed")
			delete(p.groups, group.Id)
			groups = append(groups[:i], groups[i+1:]...)
			i--
			continue
		}

		if err != nil {
			return nil, nil, err
		}
		for _, u := range users {
			userIDToGroups[u.ID] = append(userIDToGroups[u.ID], group.Id)
			userLookup[u.ID] = u
		}
	}

	var users []*directory.User
	for _, u := range userLookup {
		groups := userIDToGroups[u.ID]
		sort.Strings(groups)
		users = append(users, &directory.User{
			Id:          u.ID,
			GroupIds:    groups,
			DisplayName: u.getDisplayName(),
			Email:       u.Profile.Email,
		})
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].Id < users[j].Id
	})
	return groups, users, nil
}

func (p *Provider) getGroups(ctx context.Context) ([]*directory.Group, error) {
	u := &url.URL{Path: "/api/v1/groups"}
	q := u.Query()
	q.Set("limit", strconv.Itoa(p.cfg.batchSize))
	if p.lastUpdated != nil {
		q.Set("filter", fmt.Sprintf(`lastUpdated gt "%[1]s" or lastMembershipUpdated gt "%[1]s"`, p.lastUpdated.UTC().Format(filterDateFormat)))
	} else {
		now := time.Now()
		p.lastUpdated = &now
	}
	u.RawQuery = q.Encode()

	groupURL := p.cfg.providerURL.ResolveReference(u).String()
	for groupURL != "" {
		var out []apiGroupObject
		hdrs, err := p.apiGet(ctx, groupURL, &out)
		if err != nil {
			return nil, fmt.Errorf("okta: error querying for groups: %w", err)
		}

		for _, el := range out {
			lu, _ := time.Parse(el.LastUpdated, filterDateFormat)
			lmu, _ := time.Parse(el.LastMembershipUpdated, filterDateFormat)
			if lu.After(*p.lastUpdated) {
				p.lastUpdated = &lu
			}
			if lmu.After(*p.lastUpdated) {
				p.lastUpdated = &lmu
			}
			p.groups[el.ID] = &directory.Group{
				Id:   el.ID,
				Name: el.Profile.Name,
			}
		}
		groupURL = getNextLink(hdrs)
	}

	groups := make([]*directory.Group, 0, len(p.groups))
	for _, dg := range p.groups {
		groups = append(groups, dg)
	}
	return groups, nil
}

func (p *Provider) getGroupMembers(ctx context.Context, groupID string) (users []apiUserObject, err error) {
	usersURL := p.cfg.providerURL.ResolveReference(&url.URL{
		Path:     fmt.Sprintf("/api/v1/groups/%s/users", groupID),
		RawQuery: fmt.Sprintf("limit=%d", p.cfg.batchSize),
	}).String()
	for usersURL != "" {
		var out []apiUserObject
		hdrs, err := p.apiGet(ctx, usersURL, &out)
		if err != nil {
			return nil, fmt.Errorf("okta: error querying for groups: %w", err)
		}

		users = append(users, out...)
		usersURL = getNextLink(hdrs)
	}

	return users, nil
}

func (p *Provider) getUser(ctx context.Context, userID string) (*apiUserObject, error) {
	apiURL := p.cfg.providerURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/api/v1/users/%s", userID),
	}).String()

	var out apiUserObject
	_, err := p.apiGet(ctx, apiURL, &out)
	if err != nil {
		return nil, fmt.Errorf("okta: error querying for user: %w", err)
	}

	return &out, nil
}

func (p *Provider) listUserGroups(ctx context.Context, userID string) (groups []apiGroupObject, err error) {
	apiURL := p.cfg.providerURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/api/v1/users/%s/groups", userID),
	}).String()
	for apiURL != "" {
		var out []apiGroupObject
		hdrs, err := p.apiGet(ctx, apiURL, &out)
		if err != nil {
			return nil, fmt.Errorf("okta: error querying for user groups: %w", err)
		}
		groups = append(groups, out...)
		apiURL = getNextLink(hdrs)
	}
	return groups, nil
}

func (p *Provider) apiGet(ctx context.Context, uri string, out interface{}) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("okta: failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "SSWS "+p.cfg.serviceAccount.APIKey)

	for {
		res, err := p.cfg.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		if res.StatusCode == http.StatusTooManyRequests {
			limitReset, err := strconv.ParseInt(res.Header.Get("X-Rate-Limit-Reset"), 10, 64)
			if err == nil {
				time.Sleep(time.Until(time.Unix(limitReset, 0)))
			}
			continue
		}
		if res.StatusCode/100 != httpSuccessClass {
			return nil, newAPIError(res)
		}
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			return nil, err
		}
		return res.Header, nil
	}
}

func getNextLink(hdrs http.Header) string {
	for _, link := range linkheader.ParseMultiple(hdrs.Values("Link")) {
		if link.Rel == "next" {
			return link.URL
		}
	}
	return ""
}

// A ServiceAccount is used by the Okta provider to query the API.
type ServiceAccount struct {
	APIKey string `json:"api_key"`
}

// ParseServiceAccount parses the service account in the config options.
func ParseServiceAccount(rawServiceAccount string) (*ServiceAccount, error) {
	bs, err := base64.StdEncoding.DecodeString(rawServiceAccount)
	if err != nil {
		return nil, err
	}

	var serviceAccount ServiceAccount
	if err := json.Unmarshal(bs, &serviceAccount); err != nil {
		serviceAccount.APIKey = string(bs)
	}

	if serviceAccount.APIKey == "" {
		return nil, ErrAPIKeyRequired
	}

	return &serviceAccount, nil
}

// An APIError is an error from the okta API.
type APIError struct {
	HTTPStatusCode int
	Body           string
	ErrorCode      string   `json:"errorCode"`
	ErrorSummary   string   `json:"errorSummary"`
	ErrorLink      string   `json:"errorLink"`
	ErrorID        string   `json:"errorId"`
	ErrorCauses    []string `json:"errorCauses"`
}

func newAPIError(res *http.Response) error {
	if res == nil {
		return nil
	}
	buf, _ := ioutil.ReadAll(io.LimitReader(res.Body, readLimit)) // limit to 100kb

	err := &APIError{
		HTTPStatusCode: res.StatusCode,
		Body:           string(buf),
	}
	_ = json.Unmarshal(buf, err)
	return err
}

func (err *APIError) Error() string {
	return fmt.Sprintf("okta: error querying API, status_code=%d: %s", err.HTTPStatusCode, err.Body)
}

type (
	apiGroupObject struct {
		ID      string `json:"id"`
		Profile struct {
			Name string `json:"name"`
		} `json:"profile"`
		LastUpdated           string `json:"lastUpdated"`
		LastMembershipUpdated string `json:"lastMembershipUpdated"`
	}
	apiUserObject struct {
		ID      string `json:"id"`
		Profile struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
			Email     string `json:"email"`
		} `json:"profile"`
	}
)

func (obj *apiUserObject) getDisplayName() string {
	return obj.Profile.FirstName + " " + obj.Profile.LastName
}
