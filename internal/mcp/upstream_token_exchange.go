package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// tokenExchangeResponse represents the JSON response from an OAuth token endpoint.
type tokenExchangeResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// tokenEndpointError represents an HTTP error response from an OAuth token endpoint.
// It captures the status code so callers can distinguish permanent failures (4xx)
// from transient failures (5xx).
type tokenEndpointError struct {
	StatusCode int
	Body       string
}

func (e *tokenEndpointError) Error() string {
	return fmt.Sprintf("token endpoint returned %d: %s", e.StatusCode, e.Body)
}

// exchangeToken sends a prepared token request to an OAuth token endpoint
// and parses the JSON response.
func exchangeToken(client *http.Client, req *http.Request) (*tokenExchangeResponse, error) {
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending token request: %w", err)
	}
	defer resp.Body.Close()

	const maxTokenResponseBytes = 1 << 20 // 1 MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &tokenEndpointError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var tokenResp tokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	return &tokenResp, nil
}
