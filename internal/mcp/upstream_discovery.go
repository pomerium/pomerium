package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
)

// maxMetadataResponseBytes is the maximum size of a metadata response body.
// OAuth metadata documents are small JSON; 1 MB is generous.
const maxMetadataResponseBytes = 1 << 20

// FetchProtectedResourceMetadata fetches and parses OAuth 2.0 Protected Resource Metadata
// (RFC 9728) from the given URL. The URL is typically obtained from the resource_metadata
// parameter in a WWW-Authenticate header, or constructed as a well-known fallback.
//
// Validates that the required fields (resource, authorization_servers) are present per RFC 9728 §4.
func FetchProtectedResourceMetadata(
	ctx context.Context,
	client *http.Client,
	metadataURL string,
) (*ProtectedResourceMetadata, error) {
	var meta ProtectedResourceMetadata
	if err := fetchJSON(ctx, client, metadataURL, &meta); err != nil {
		return nil, err
	}
	if err := ValidateProtectedResourceMetadata(&meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// FetchAuthorizationServerMetadata fetches and parses OAuth 2.0 Authorization Server Metadata
// (RFC 8414) from the given issuer URL. It tries endpoints in the MCP-specified priority order:
//
// For issuer URLs with path components:
//  1. {origin}/.well-known/oauth-authorization-server/{path}
//  2. {origin}/.well-known/openid-configuration/{path}
//  3. {origin}/{path}/.well-known/openid-configuration
//
// For issuer URLs without path:
//  1. {origin}/.well-known/oauth-authorization-server
//  2. {origin}/.well-known/openid-configuration
//
// Validates MCP requirements: code_challenge_methods_supported MUST include "S256",
// grant_types_supported MUST include "authorization_code".
func FetchAuthorizationServerMetadata(
	ctx context.Context,
	client *http.Client,
	issuerURL string,
) (*AuthorizationServerMetadata, error) {
	urls, err := BuildAuthorizationServerMetadataURLs(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("building AS metadata URLs: %w", err)
	}

	var lastErr error
	for _, u := range urls {
		var meta AuthorizationServerMetadata
		if err := fetchJSON(ctx, client, u, &meta); err != nil {
			lastErr = err
			continue
		}
		if err := ValidateAuthorizationServerMetadata(&meta); err != nil {
			lastErr = err
			continue
		}
		return &meta, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("authorization server metadata not found at any well-known endpoint: %w", lastErr)
	}
	return nil, fmt.Errorf("authorization server metadata not found at any well-known endpoint")
}

// BuildProtectedResourceMetadataURLs returns the well-known URLs to probe for
// Protected Resource Metadata when the WWW-Authenticate header lacks a resource_metadata parameter.
//
// Per RFC 9728, the well-known path is /.well-known/oauth-protected-resource.
// For URLs with path components, it returns both the path-suffixed and root variants.
func BuildProtectedResourceMetadataURLs(upstreamURL string) ([]string, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL: %w", err)
	}

	origin := url.URL{Scheme: u.Scheme, Host: u.Host}
	p := strings.TrimSuffix(u.Path, "/")

	if p == "" {
		return []string{
			origin.String() + WellKnownProtectedResourceEndpoint,
		}, nil
	}

	return []string{
		origin.String() + path.Join(WellKnownProtectedResourceEndpoint, p),
		origin.String() + WellKnownProtectedResourceEndpoint,
	}, nil
}

// BuildAuthorizationServerMetadataURLs returns the well-known URLs to try for
// Authorization Server Metadata discovery in the MCP-specified priority order.
func BuildAuthorizationServerMetadataURLs(issuerURL string) ([]string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer URL: %w", err)
	}

	origin := url.URL{Scheme: u.Scheme, Host: u.Host}
	p := strings.TrimSuffix(u.Path, "/")

	if p == "" {
		return []string{
			origin.String() + "/.well-known/oauth-authorization-server",
			origin.String() + "/.well-known/openid-configuration",
		}, nil
	}

	return []string{
		origin.String() + "/.well-known/oauth-authorization-server" + p,
		origin.String() + "/.well-known/openid-configuration" + p,
		origin.String() + p + "/.well-known/openid-configuration",
	}, nil
}

// ValidateProtectedResourceMetadata validates that a ProtectedResourceMetadata
// document contains the required fields per RFC 9728 §4.
func ValidateProtectedResourceMetadata(meta *ProtectedResourceMetadata) error {
	if meta == nil {
		return fmt.Errorf("nil protected resource metadata")
	}
	if meta.Resource == "" {
		return fmt.Errorf("protected resource metadata: resource is required")
	}
	if len(meta.AuthorizationServers) == 0 {
		return fmt.Errorf("protected resource metadata: authorization_servers must contain at least one entry")
	}
	return nil
}

// ValidateAuthorizationServerMetadata validates that an AuthorizationServerMetadata
// document meets MCP requirements:
// - code_challenge_methods_supported MUST include "S256" (MCP requires PKCE)
// - grant_types_supported MUST include "authorization_code"
func ValidateAuthorizationServerMetadata(meta *AuthorizationServerMetadata) error {
	if meta == nil {
		return fmt.Errorf("nil authorization server metadata")
	}
	if !slices.Contains(meta.CodeChallengeMethodsSupported, "S256") {
		return fmt.Errorf("authorization server metadata: code_challenge_methods_supported must include S256 (MCP requires PKCE)")
	}
	// Per RFC 8414 §2, if grant_types_supported is omitted, the default is
	// ["authorization_code", "implicit"], which includes authorization_code.
	if meta.GrantTypesSupported != nil && !slices.Contains(meta.GrantTypesSupported, "authorization_code") {
		return fmt.Errorf("authorization server metadata: grant_types_supported must include authorization_code")
	}
	return nil
}

// fetchJSON fetches a URL and decodes the JSON response into dst.
// Returns an error if the response status is not 200 OK.
func fetchJSON(ctx context.Context, client *http.Client, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: unexpected status %d", url, resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxMetadataResponseBytes)).Decode(dst); err != nil {
		return fmt.Errorf("decoding JSON from %s: %w", url, err)
	}
	return nil
}
