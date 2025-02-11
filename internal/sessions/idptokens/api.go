package idptokens

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/urlutil"
)

// endpoints
const (
	VerifyAccessTokenEndpoint   = "verify-access-token"
	VerifyIdentityTokenEndpoint = "verify-identity-token"
)

// A VerifyTokenResponse is the response to verifying an access token or identity token.
type VerifyTokenResponse struct {
	Valid  bool           `json:"valid"`
	Error  string         `json:"error,omitempty"`
	Claims map[string]any `json:"claims,omitempty"`
}

// VerifyAccessTokenRequest is the data for verifying an access token.
type VerifyAccessTokenRequest struct {
	AccessToken        string `json:"accessToken"`
	IdentityProviderID string `json:"identityProviderId,omitempty"`
}

// VerifyIdentityTokenRequest is the data for verifying an identity token.
type VerifyIdentityTokenRequest struct {
	IdentityToken      string `json:"identityToken"`
	IdentityProviderID string `json:"identityProviderId,omitempty"`
}

func apiVerifyAccessToken(
	ctx context.Context,
	authenticateServiceURL string,
	request *VerifyAccessTokenRequest,
) (*VerifyTokenResponse, error) {
	var response VerifyTokenResponse
	err := api(ctx, authenticateServiceURL, "verify-access-token", request, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func apiVerifyIdentityToken(
	ctx context.Context,
	authenticateServiceURL string,
	request *VerifyIdentityTokenRequest,
) (*VerifyTokenResponse, error) {
	var response VerifyTokenResponse
	err := api(ctx, authenticateServiceURL, "verify-identity-token", request, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func api(
	ctx context.Context,
	authenticateServiceURL string,
	endpoint string,
	request, response any,
) error {
	u, err := urlutil.ParseAndValidateURL(authenticateServiceURL)
	if err != nil {
		return fmt.Errorf("invalid authenticate service url: %w", err)
	}
	u = u.ResolveReference(&url.URL{
		Path: "/.pomerium/" + endpoint,
	})

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("error marshaling %s http request: %w", endpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error creating %s http request: %w", endpoint, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error executing %s http request: %w", endpoint, err)
	}
	defer res.Body.Close()

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading %s http response: %w", endpoint, err)
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return fmt.Errorf("error reading %s http response (body=%s): %w", endpoint, body, err)
	}

	return nil
}
