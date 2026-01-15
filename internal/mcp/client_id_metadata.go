package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

// ClientIDMetadataDocument represents the metadata document fetched from a URL-based client_id.
// Per draft-ietf-oauth-client-id-metadata-document, the document must contain a client_id
// that matches the URL exactly.
type ClientIDMetadataDocument struct {
	// ClientID MUST match the URL of the document.
	ClientID string `json:"client_id"`

	// ClientName is OPTIONAL but RECOMMENDED.
	ClientName string `json:"client_name,omitempty"`

	// ClientURI is OPTIONAL.
	ClientURI string `json:"client_uri,omitempty"`

	// LogoURI is OPTIONAL.
	LogoURI string `json:"logo_uri,omitempty"`

	// RedirectURIs is REQUIRED for authorization code flow.
	RedirectURIs []string `json:"redirect_uris"`

	// GrantTypes is OPTIONAL. Defaults to ["authorization_code"].
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes is OPTIONAL. Defaults to ["code"].
	ResponseTypes []string `json:"response_types,omitempty"`

	// TokenEndpointAuthMethod is OPTIONAL. Defaults to "none" for public clients.
	// Per draft, MUST NOT be client_secret_basic, client_secret_post, client_secret_jwt.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// Scope is OPTIONAL.
	Scope string `json:"scope,omitempty"`

	// Contacts is OPTIONAL.
	Contacts []string `json:"contacts,omitempty"`

	// TOSURI is OPTIONAL.
	TOSURI string `json:"tos_uri,omitempty"`

	// PolicyURI is OPTIONAL.
	PolicyURI string `json:"policy_uri,omitempty"`

	// JWKSURI is OPTIONAL.
	JWKSURI string `json:"jwks_uri,omitempty"`

	// SoftwareID is OPTIONAL.
	SoftwareID string `json:"software_id,omitempty"`

	// SoftwareVersion is OPTIONAL.
	SoftwareVersion string `json:"software_version,omitempty"`
}

// MaxClientMetadataDocumentSize is the maximum size of a client metadata document (5KB per draft recommendation).
const MaxClientMetadataDocumentSize = 5 * 1024

// DefaultHTTPClient is the default HTTP client used for fetching client metadata documents.
// This can be overridden to provide custom TLS configuration or security measures.
// If nil, http.DefaultClient is used.
var DefaultHTTPClient *http.Client

// ClientMetadataFetcher fetches and validates client metadata documents.
type ClientMetadataFetcher struct {
	httpClient    *http.Client
	domainMatcher *DomainMatcher
}

// NewClientMetadataFetcher creates a new ClientMetadataFetcher.
// If httpClient is nil, DefaultHTTPClient is used (or http.DefaultClient if DefaultHTTPClient is also nil).
// If domainMatcher is nil, all domains are rejected (empty allowlist behavior).
// Callers may provide a custom http.Client to implement SSRF protection or other security measures.
func NewClientMetadataFetcher(httpClient *http.Client, domainMatcher *DomainMatcher) *ClientMetadataFetcher {
	if httpClient == nil {
		httpClient = DefaultHTTPClient
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &ClientMetadataFetcher{
		httpClient:    httpClient,
		domainMatcher: domainMatcher,
	}
}

// IsClientIDMetadataURL checks if the client_id is a URL pointing to a metadata document.
// Per draft-ietf-oauth-client-id-metadata-document Section 3, client identifier URLs:
// - MUST have "https" scheme
// - MUST contain a path component
// - MUST NOT contain single-dot or double-dot path segments
// - MUST NOT contain a fragment component
// - MUST NOT contain username or password
// - SHOULD NOT include a query string component
// - MAY contain a port
//
// Returns (false, nil) if clientID is not a URL (e.g., a regular client ID string).
// Returns (false, error) if clientID is a URL but violates RFC requirements.
// Returns (true, nil) if clientID is a valid client ID metadata URL.
func IsClientIDMetadataURL(clientID string) (bool, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return false, nil // Not a valid URL, treat as regular client ID
	}

	// Not HTTPS means it's not a client ID metadata URL
	// (could be a regular client ID string or http URL which we don't support)
	if u.Scheme != "https" {
		return false, nil
	}

	// From here on, we have an HTTPS URL, so RFC requirements apply
	// and violations should return errors

	// Must have a host
	if u.Host == "" {
		return false, fmt.Errorf("%w: client_id URL must have a host", ErrClientMetadataValidation)
	}

	// Must have a path component
	if u.Path == "" || u.Path == "/" {
		return false, fmt.Errorf("%w: client_id URL must contain a path component", ErrClientMetadataValidation)
	}

	// Must not contain . or .. path segments
	segments := strings.Split(u.Path, "/")
	for _, seg := range segments {
		if seg == "." || seg == ".." {
			return false, fmt.Errorf("%w: client_id URL must not contain single-dot or double-dot path segments", ErrClientMetadataValidation)
		}
	}

	// Must not have fragment
	if u.Fragment != "" {
		return false, fmt.Errorf("%w: client_id URL must not contain a fragment component", ErrClientMetadataValidation)
	}

	// Must not have username or password
	if u.User != nil {
		return false, fmt.Errorf("%w: client_id URL must not contain username or password", ErrClientMetadataValidation)
	}

	// SHOULD NOT include a query string - we treat this as an error per RFC guidance
	if u.RawQuery != "" {
		return false, fmt.Errorf("%w: client_id URL should not include a query string", ErrClientMetadataValidation)
	}

	return true, nil
}

// ErrClientMetadataFetch represents an error fetching client metadata.
var ErrClientMetadataFetch = errors.New("failed to fetch client metadata")

// ErrClientMetadataValidation represents a validation error for client metadata.
var ErrClientMetadataValidation = errors.New("client metadata validation failed")

// Fetch retrieves and validates a client metadata document from the given URL.
func (f *ClientMetadataFetcher) Fetch(ctx context.Context, clientIDURL string) (*ClientIDMetadataDocument, error) {
	isURL, err := IsClientIDMetadataURL(clientIDURL)
	if err != nil {
		return nil, err
	}
	if !isURL {
		return nil, fmt.Errorf("%w: client_id is not a valid metadata URL", ErrClientMetadataValidation)
	}

	// Check if domain is allowed BEFORE making any HTTP request
	u, _ := url.Parse(clientIDURL) // Already validated by IsClientIDMetadataURL
	if f.domainMatcher == nil {
		return nil, fmt.Errorf("%w: no allowed domains configured", ErrDomainNotAllowed)
	}
	if err := f.domainMatcher.ValidateURLDomain(u); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientMetadataValidation, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientIDURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientMetadataFetch, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientMetadataFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP status %d", ErrClientMetadataFetch, resp.StatusCode)
	}

	// Limit response size to prevent DoS
	limitedReader := io.LimitReader(resp.Body, MaxClientMetadataDocumentSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %w", ErrClientMetadataFetch, err)
	}
	if len(data) > MaxClientMetadataDocumentSize {
		return nil, fmt.Errorf("%w: response exceeds maximum size of %d bytes", ErrClientMetadataFetch, MaxClientMetadataDocumentSize)
	}

	var doc ClientIDMetadataDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %w", ErrClientMetadataFetch, err)
	}

	// Validate: client_id in document MUST match the URL exactly (simple string comparison per RFC 3986 Section 6.2.1)
	if doc.ClientID != clientIDURL {
		return nil, fmt.Errorf("%w: client_id in document (%q) does not match URL (%q)", ErrClientMetadataValidation, doc.ClientID, clientIDURL)
	}

	// Validate: redirect_uris is required
	if len(doc.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%w: redirect_uris is required", ErrClientMetadataValidation)
	}

	// Validate: token_endpoint_auth_method must not be secret-based
	if doc.TokenEndpointAuthMethod != "" {
		switch doc.TokenEndpointAuthMethod {
		case "client_secret_basic", "client_secret_post", "client_secret_jwt":
			return nil, fmt.Errorf("%w: token_endpoint_auth_method %q is not allowed for client metadata documents",
				ErrClientMetadataValidation, doc.TokenEndpointAuthMethod)
		}
	}

	return &doc, nil
}

// ToClientRegistration converts a ClientIDMetadataDocument to a ClientRegistration
// for use in the authorization flow.
func (doc *ClientIDMetadataDocument) ToClientRegistration() *rfc7591v1.ClientRegistration {
	grantTypes := doc.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{rfc7591v1.GrantTypesAuthorizationCode}
	}

	responseTypes := doc.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{rfc7591v1.ResponseTypesCode}
	}

	tokenEndpointAuthMethod := doc.TokenEndpointAuthMethod
	if tokenEndpointAuthMethod == "" {
		tokenEndpointAuthMethod = rfc7591v1.TokenEndpointAuthMethodNone
	}

	metadata := &rfc7591v1.Metadata{
		RedirectUris:            doc.RedirectURIs,
		TokenEndpointAuthMethod: &tokenEndpointAuthMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
	}

	if doc.ClientName != "" {
		metadata.ClientName = &doc.ClientName
	}
	if doc.ClientURI != "" {
		metadata.ClientUri = &doc.ClientURI
	}
	if doc.LogoURI != "" {
		metadata.LogoUri = &doc.LogoURI
	}
	if doc.Scope != "" {
		metadata.Scope = &doc.Scope
	}
	if doc.TOSURI != "" {
		metadata.TosUri = &doc.TOSURI
	}
	if doc.PolicyURI != "" {
		metadata.PolicyUri = &doc.PolicyURI
	}
	if doc.JWKSURI != "" {
		metadata.JwksUri = &doc.JWKSURI
	}
	if doc.SoftwareID != "" {
		metadata.SoftwareId = &doc.SoftwareID
	}
	if doc.SoftwareVersion != "" {
		metadata.SoftwareVersion = &doc.SoftwareVersion
	}
	if len(doc.Contacts) > 0 {
		metadata.Contacts = doc.Contacts
	}

	return &rfc7591v1.ClientRegistration{
		RequestMetadata:  metadata,
		ResponseMetadata: metadata,
		// No ClientSecret for metadata document clients
	}
}

// ValidateRedirectURI checks if the given redirect_uri is in the list of allowed redirect URIs.
func (doc *ClientIDMetadataDocument) ValidateRedirectURI(redirectURI string) error {
	for _, allowed := range doc.RedirectURIs {
		if allowed == redirectURI {
			return nil
		}
	}
	return fmt.Errorf("%w: redirect_uri %q is not in the list of registered redirect URIs", ErrClientMetadataValidation, redirectURI)
}
