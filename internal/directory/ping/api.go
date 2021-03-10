package ping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var errNotFound = errors.New("ping: user not found")

type (
	apiGroup struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	apiUser struct {
		ID               string      `json:"id"`
		Email            string      `json:"email"`
		Name             apiUserName `json:"name"`
		Username         string      `json:"username"`
		MemberOfGroupIDs []string    `json:"memberOfGroupIDs"`
	}
	apiUserName struct {
		Given  string `json:"given"`
		Middle string `json:"middle"`
		Family string `json:"family"`
	}
)

func (au apiUser) getDisplayName() string {
	var parts []string
	if au.Name.Given != "" {
		parts = append(parts, au.Name.Given)
	}
	if au.Name.Middle != "" {
		parts = append(parts, au.Name.Middle)
	}
	if au.Name.Family != "" {
		parts = append(parts, au.Name.Family)
	}
	if len(parts) == 0 {
		parts = append(parts, au.Username)
	}
	return strings.Join(parts, " ")
}

func getAllGroups(ctx context.Context, client *http.Client, apiURL *url.URL, envID string) ([]apiGroup, error) {
	nextURL := apiURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/v1/environments/%s/groups", envID),
	}).String()

	var apiGroups []apiGroup
	err := batchAPIRequest(ctx, client, nextURL, func(body []byte) error {
		var apiResponse struct {
			Embedded struct {
				Groups []apiGroup `json:"groups"`
			} `json:"_embedded"`
		}
		err := json.Unmarshal(body, &apiResponse)
		if err != nil {
			return fmt.Errorf("ping: error decoding API response: %w", err)
		}
		apiGroups = append(apiGroups, apiResponse.Embedded.Groups...)
		return nil
	})
	return apiGroups, err
}

func getGroupUsers(ctx context.Context, client *http.Client, apiURL *url.URL, envID, groupID string) ([]apiUser, error) {
	nextURL := apiURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/v1/environments/%s/users", envID),
		RawQuery: (&url.Values{
			"filter": {fmt.Sprintf(`memberOfGroups[id eq "%s"]`, groupID)},
		}).Encode(),
	}).String()

	var apiUsers []apiUser
	err := batchAPIRequest(ctx, client, nextURL, func(body []byte) error {
		var apiResponse struct {
			Embedded struct {
				Users []apiUser `json:"users"`
			} `json:"_embedded"`
		}
		err := json.Unmarshal(body, &apiResponse)
		if err != nil {
			return fmt.Errorf("ping: error decoding API response: %w", err)
		}
		apiUsers = append(apiUsers, apiResponse.Embedded.Users...)
		return nil
	})
	return apiUsers, err
}

func getUser(ctx context.Context, client *http.Client, apiURL *url.URL, envID, userID string) (*apiUser, error) {
	nextURL := apiURL.ResolveReference(&url.URL{
		Path: fmt.Sprintf("/v1/environments/%s/users/%s", envID, userID),
		RawQuery: (&url.Values{
			"include": {"memberOfGroupIDs"},
		}).Encode(),
	}).String()

	req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ping: error building API request: %w", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ping: error making API request: %w", err)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("ping: error reading API response: %w", err)
	}
	_ = res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	} else if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ping: unexpected status code: %d", res.StatusCode)
	}

	var u apiUser
	err = json.Unmarshal(body, &u)
	if err != nil {
		return nil, fmt.Errorf("ping: error decoding API response: %w", err)
	}
	return &u, nil
}

func batchAPIRequest(ctx context.Context, client *http.Client, nextURL string, callback func(body []byte) error) error {
	for nextURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
		if err != nil {
			return fmt.Errorf("ping: error building API request: %w", err)
		}

		res, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("ping: error making API request: %w", err)
		}
		bs, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("ping: error reading API response: %w", err)
		}
		_ = res.Body.Close()
		if res.StatusCode/100 != 2 {
			return fmt.Errorf("ping: unexpected status code: %d", res.StatusCode)
		}

		var apiResponse struct {
			Links struct {
				Next struct {
					HREF string `json:"href"`
				} `json:"next"`
			} `json:"_links"`
		}
		err = json.Unmarshal(bs, &apiResponse)
		if err != nil {
			return fmt.Errorf("ping: error decoding API response: %w", err)
		}

		err = callback(bs)
		if err != nil {
			return err
		}

		nextURL = apiResponse.Links.Next.HREF
	}
	return nil
}
