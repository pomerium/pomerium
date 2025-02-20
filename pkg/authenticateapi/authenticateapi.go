// Package authenticateapi has the types and methods for the authenticate api.
package authenticateapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/jwtutil"
)

// VerifyAccessTokenRequest is used to verify access tokens.
type VerifyAccessTokenRequest struct {
	AccessToken        string `json:"accessToken"`
	IdentityProviderID string `json:"identityProviderId,omitempty"`
}

// VerifyIdentityTokenRequest is used to verify identity tokens.
type VerifyIdentityTokenRequest struct {
	IdentityToken      string `json:"identityToken"`
	IdentityProviderID string `json:"identityProviderId,omitempty"`
}

// VerifyTokenResponse is the result of verifying an access or identity token.
type VerifyTokenResponse struct {
	Valid  bool           `json:"valid"`
	Claims jwtutil.Claims `json:"claims,omitempty"`
}

// An API is an api client for the authenticate service.
type API struct {
	authenticateURL *url.URL
	transport       http.RoundTripper
}

// New creates a new API client.
func New(
	authenticateURL *url.URL,
	transport http.RoundTripper,
) *API {
	return &API{
		authenticateURL: authenticateURL,
		transport:       transport,
	}
}

// VerifyAccessToken verifies an access token.
func (api *API) VerifyAccessToken(ctx context.Context, request *VerifyAccessTokenRequest) (*VerifyTokenResponse, error) {
	var response VerifyTokenResponse
	err := api.call(ctx, "verify-access-token", request, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// VerifyIdentityToken verifies an identity token.
func (api *API) VerifyIdentityToken(ctx context.Context, request *VerifyIdentityTokenRequest) (*VerifyTokenResponse, error) {
	var response VerifyTokenResponse
	err := api.call(ctx, "verify-identity-token", request, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func (api *API) call(
	ctx context.Context,
	endpoint string,
	request, response any,
) error {
	u := api.authenticateURL.ResolveReference(&url.URL{
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

	res, err := (&http.Client{
		Transport: api.transport,
	}).Do(req)
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
