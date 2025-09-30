package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	go_oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// StartDeviceAuthorizationFlow starts the OAuth 2.0 Device Authorization Grant using the
// discovery-provided device_authorization_endpoint.
func StartDeviceAuthorizationFlow(ctx context.Context, provider *go_oidc.Provider, clientID, clientSecret string, scopes []string) (*oauth2.DeviceAuthResponse, error) {
	var discovery struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := provider.Claims(&discovery); err != nil {
		return nil, fmt.Errorf("oidc: unable to read discovery claims: %w", err)
	}
	if discovery.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("oidc: identity provider does not advertise device_authorization_endpoint")
	}

	values := url.Values{}
	values.Set("client_id", clientID)
	if clientSecret != "" {
		// Many IdPs require client authentication for the device authorization endpoint
		// when the client is confidential. Use client_secret_post.
		values.Set("client_secret", clientSecret)
	}
	if len(scopes) > 0 {
		values.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.DeviceAuthorizationEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization failed: %s", http.StatusText(resp.StatusCode))
	}

	var out oauth2.DeviceAuthResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
