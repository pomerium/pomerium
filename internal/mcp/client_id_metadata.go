package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	go_oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/pomerium/pomerium/internal/httputil"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/internal/version"
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

	// RFC8414 Oauth 2.0 Server Metadata
	// OPTIONAL. JSON array containing a list of client authentication
	// methods supported by this token endpoint.  Client authentication
	// method values are used in the "token_endpoint_auth_method". See above.
	TokendEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

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

// ClientMetadataFetcher fetches and validates client metadata documents.
type ClientMetadataFetcher struct {
	httpClient    *http.Client
	domainMatcher *DomainMatcher
}

// NewClientMetadataFetcher creates a new ClientMetadataFetcher.
// httpClient must be non-nil and should be an SSRF-safe client (e.g. from NewSSRFSafeClient()).
// If domainMatcher is nil, all domains are rejected (empty allowlist behavior).
func NewClientMetadataFetcher(httpClient *http.Client, domainMatcher *DomainMatcher) *ClientMetadataFetcher {
	if httpClient == nil {
		panic("NewClientMetadataFetcher: httpClient must not be nil")
	}
	return &ClientMetadataFetcher{
		httpClient:    httputil.NewSizeLimitClient(httpClient, MaxClientMetadataDocumentSize),
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
// - MAY contain a port
//
// A query string SHOULD NOT be included per the draft, but because that is a
// recommendation rather than a requirement we tolerate it.
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
	segments := strings.SplitSeq(u.Path, "/")
	for seg := range segments {
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

	u, _ := url.Parse(clientIDURL) // already validated by previous check
	if err := f.domainMatcher.ValidateURLDomain(u); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientMetadataValidation, err)
	}

	var doc ClientIDMetadataDocument
	if err := f.fetchJSON(ctx, clientIDURL, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientMetadataFetch, err)
	}

	// Validate: client_id in document MUST match the URL exactly (simple string comparison per RFC 3986 Section 6.2.1)
	if doc.ClientID != clientIDURL {
		return nil, fmt.Errorf("%w: client_id in document (%q) does not match URL (%q)", ErrClientMetadataValidation, doc.ClientID, clientIDURL)
	}

	return &doc, nil
}

// Validate does static validation that the CIMD has fields that make sense
// with the provided information.
func (doc *ClientIDMetadataDocument) Validate() error {
	if len(doc.RedirectURIs) == 0 {
		return fmt.Errorf("%w: redirect_uris is required", ErrClientMetadataValidation)
	}

	switch doc.TokenEndpointAuthMethod {
	case "client_secret_basic", "client_secret_post", "client_secret_jwt":
		return fmt.Errorf("%w: token_endpoint_auth_method %q is not allowed for client metadata documents",
			ErrClientMetadataValidation, doc.TokenEndpointAuthMethod)
	}

	if err := doc.validateKeySet(); err != nil {
		return fmt.Errorf("%w: %w", ErrClientMetadataValidation, err)
	}
	return nil
}

// canAuthenticateWith reports whether the document carries the material a given
// token endpoint auth method needs. It is consulted only when negotiating among
// the alternatives a client advertises; a method the client explicitly asked for
// is still validated strictly, so a misconfiguration stays an error rather than
// becoming a silent downgrade. Methods added to supportedTokenAuthMethodsForCIMD
// need a case here, hence the closed switch.
func (doc *ClientIDMetadataDocument) canAuthenticateWith(method string) bool {
	switch method {
	case rfc7591v1.TokenEndpointAuthMethodNone:
		return true
	case rfc7591v1.TokenEndpointAuthMethodPrivateKeyJWT:
		return doc.JWKSURI != ""
	default:
		return false
	}
}

func (doc *ClientIDMetadataDocument) validateKeySet() error {
	if doc.JWKSURI != "" {
		u, err := url.Parse(doc.JWKSURI)
		if err != nil {
			return fmt.Errorf("jwks_uri is not a valid URL: %w", err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("jwks_uri must use the https scheme")
		}
	}

	if doc.TokenEndpointAuthMethod == rfc7591v1.TokenEndpointAuthMethodPrivateKeyJWT && doc.JWKSURI == "" {
		return fmt.Errorf("token_endpoint_auth_method %q requires jwks_uri", doc.TokenEndpointAuthMethod)
	}
	return nil
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
	if slices.Contains(doc.RedirectURIs, redirectURI) {
		return nil
	}
	return fmt.Errorf("%w: redirect_uri %q is not in the list of registered redirect URIs", ErrClientMetadataValidation, redirectURI)
}

func (f *ClientMetadataFetcher) fetchJSON(ctx context.Context, rawURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	return nil
}

// MaxJWKSSize is the maximum size of a fetched JSON Web Key Set.
// While there's no maximum size enforced by an RFC, it is provided by the CIMD
// document so it's probably a good idea to guard against DoS.
// From looking around at implementations/best practices, 1MB seems to be a reasonable cap.
const MaxJWKSSize = 1024 * 1024 // 1MB

var ErrJWKSFetch = errors.New("failed to fetch client JWKS")

// JWKSKeySetCacheSize bounds how many distinct jwks_uri key sets are retained.
// jwks_uri comes from client-controlled metadata, so this must stay bounded.
const JWKSKeySetCacheSize = 256

// JWKSKeySetCacheTTL bounds how long a withdrawn jwks_uri keeps serving from
// cache. Rotation to a new key needs no TTL: a key set refetches on an unknown
// kid.
const JWKSKeySetCacheTTL = 30 * time.Minute

// JWKSFetcher fetches client-side jwks_uris for validation
type JWKSFetcher struct {
	httpClient    *http.Client
	domainMatcher *DomainMatcher
	keySets       *expirable.LRU[string, *go_oidc.RemoteKeySet]
}

func NewJWKSFetcher(httpClient *http.Client, domainMatcher *DomainMatcher) *JWKSFetcher {
	if httpClient == nil {
		panic("NewJWKSFetcher: httpClient must not be nil")
	}
	keySets := expirable.NewLRU[string, *go_oidc.RemoteKeySet](JWKSKeySetCacheSize, nil, JWKSKeySetCacheTTL)
	return &JWKSFetcher{
		httpClient:    httputil.NewSizeLimitClient(httpClient, MaxJWKSSize),
		domainMatcher: domainMatcher,
		keySets:       keySets,
	}
}

func (j *JWKSFetcher) KeySet(ctx context.Context, jwksURI string) (*go_oidc.RemoteKeySet, error) {
	if jwksURI == "" {
		return nil, fmt.Errorf("%w: empty jwks_uri", ErrJWKSFetch)
	}
	u, err := url.Parse(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid jwks_uri: %w", ErrJWKSFetch, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: jwks_uri must use the https scheme", ErrJWKSFetch)
	}
	if err := j.domainMatcher.ValidateURLDomain(u); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	if ks, ok := j.keySets.Get(jwksURI); ok {
		return ks, nil
	}

	// A RemoteKeySet caches keys and coalesces in-flight fetches internally, but
	// only per instance, so it has to outlive the request that created it. It
	// retains the context it is built from, so that must not be the request's:
	// that would pin request-scoped values for as long as the entry is cached.
	ks := go_oidc.NewRemoteKeySet(
		go_oidc.ClientContext(context.Background(), j.httpClient),
		jwksURI,
	)
	j.keySets.Add(jwksURI, ks)
	return ks, nil
}
