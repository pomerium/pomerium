package mcp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/shogo82148/go-sfv"
)

// AuthorizationServerMetadata represents the OAuth 2.0 Authorization Server Metadata (RFC 8414).
// https://datatracker.ietf.org/doc/html/rfc8414#section-2
type AuthorizationServerMetadata struct {
	// Issuer is REQUIRED. The authorization server's issuer identifier, a URL using the "https" scheme with no query or fragment.
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the URL of the authorization server's authorization endpoint. REQUIRED unless no grant types use the authorization endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`

	// TokenEndpoint is the URL of the authorization server's token endpoint. REQUIRED unless only the implicit grant type is supported.
	TokenEndpoint string `json:"token_endpoint,omitempty"`

	// JwksURI is OPTIONAL. URL of the authorization server's JWK Set document.
	JwksURI string `json:"jwks_uri,omitempty"`

	// RegistrationEndpoint is OPTIONAL. URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// ScopesSupported is RECOMMENDED. JSON array of supported OAuth 2.0 "scope" values.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResponseTypesSupported is REQUIRED. JSON array of supported OAuth 2.0 "response_type" values.
	ResponseTypesSupported []string `json:"response_types_supported"`

	// ResponseModesSupported is OPTIONAL. JSON array of supported OAuth 2.0 "response_mode" values. Default: ["query", "fragment"].
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// GrantTypesSupported is OPTIONAL. JSON array of supported OAuth 2.0 grant type values. Default: ["authorization_code", "implicit"].
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported is OPTIONAL. JSON array of client authentication methods supported by the token endpoint. Default: "client_secret_basic".
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// TokenEndpointAuthSigningAlgValuesSupported is OPTIONAL. JSON array of JWS signing algorithms supported by the token endpoint for JWT client authentication.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// ServiceDocumentation is OPTIONAL. URL of a page with human-readable information for developers.
	ServiceDocumentation string `json:"service_documentation,omitempty"`

	// UILocalesSupported is OPTIONAL. JSON array of supported languages and scripts for the UI, as BCP 47 language tags.
	UILocalesSupported []string `json:"ui_locales_supported,omitempty"`

	// OpPolicyURI is OPTIONAL. URL for the authorization server's policy on client data usage.
	OpPolicyURI string `json:"op_policy_uri,omitempty"`

	// OpTosURI is OPTIONAL. URL for the authorization server's terms of service.
	OpTosURI string `json:"op_tos_uri,omitempty"`

	// RevocationEndpoint is OPTIONAL. URL of the authorization server's OAuth 2.0 revocation endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// RevocationEndpointAuthMethodsSupported is OPTIONAL. JSON array of client authentication methods supported by the revocation endpoint. Default: "client_secret_basic".
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// RevocationEndpointAuthSigningAlgValuesSupported is OPTIONAL. JSON array of JWS signing algorithms supported by the revocation endpoint for JWT client authentication.
	RevocationEndpointAuthSigningAlgValuesSupported []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	// IntrospectionEndpoint is OPTIONAL. URL of the authorization server's OAuth 2.0 introspection endpoint.
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// IntrospectionEndpointAuthMethodsSupported is OPTIONAL. JSON array of client authentication methods supported by the introspection endpoint.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// IntrospectionEndpointAuthSigningAlgValuesSupported is OPTIONAL. JSON array of JWS signing algorithms supported by the introspection endpoint for JWT client authentication.
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`

	// CodeChallengeMethodsSupported is OPTIONAL. JSON array of PKCE code challenge methods supported by this authorization server.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// ProtectedResourceMetadata represents OAuth Protected Resource Metadata.
// see https://datatracker.ietf.org/doc/html/rfc9728#name-protected-resource-metadata
type ProtectedResourceMetadata struct {
	// Resource is REQUIRED. The protected resource's resource identifier.
	Resource string `json:"resource"`

	// AuthorizationServers is OPTIONAL. List of OAuth authorization server issuer identifiers (RFC 8414).
	AuthorizationServers []string `json:"authorization_servers,omitempty"`

	// JwksURI is OPTIONAL. URL of the protected resource's JWK Set (must use https).
	JwksURI string `json:"jwks_uri,omitempty"`

	// ScopesSupported is RECOMMENDED. List of scope values used in authorization requests to access this resource.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// BearerMethodsSupported is OPTIONAL. Supported methods of sending a bearer token (RFC 6750): header, body, query.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ResourceSigningAlgValuesSupported is OPTIONAL. JWS signing algorithms supported for signing resource responses (value "none" MUST NOT be used).
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported,omitempty"`

	// ResourceName is RECOMMENDED. Human‑readable, end‑user display name (internationalizable).
	ResourceName string `json:"resource_name,omitempty"`

	// ResourceDocumentation is OPTIONAL. URL with human‑readable developer information (internationalizable).
	ResourceDocumentation string `json:"resource_documentation,omitempty"`

	// ResourcePolicyURI is OPTIONAL. URL describing data usage requirements (internationalizable).
	ResourcePolicyURI string `json:"resource_policy_uri,omitempty"`

	// ResourceTOSURI is OPTIONAL. URL with terms of service (internationalizable).
	ResourceTOSURI string `json:"resource_tos_uri,omitempty"`

	// TLSClientCertificateBoundAccessTokens is OPTIONAL. Indicates support for mutual‑TLS certificate-bound access tokens (RFC 8705). Default false when omitted.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// AuthorizationDetailsTypesSupported is OPTIONAL. Authorization details type values supported (RFC 9396).
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	// DPoPSigningAlgValuesSupported is OPTIONAL. JWS alg values supported for validating DPoP proofs (RFC 9449).
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// DPoPBoundAccessTokensRequired is OPTIONAL. Whether DPoP-bound access tokens are always required. Default false when omitted.
	DPoPBoundAccessTokensRequired bool `json:"dpop_bound_access_tokens_required,omitempty"`
}

func AuthorizationServerMetadataHandler(prefix string) http.HandlerFunc {
	return getMetadataHandler(getAuthorizationServerMetadata, prefix)
}

func ProtectedResourceMetadataHandler(prefix string) http.HandlerFunc {
	return getMetadataHandler(getProtectedResourceMetadata, prefix)
}

func getAuthorizationServerMetadata(r *http.Request, prefix string) AuthorizationServerMetadata {
	baseURL := url.URL{
		Scheme: "https",
		Host:   r.Host,
	}
	P := func(path string) string {
		u := baseURL
		u.Path = path
		return u.String()
	}

	return AuthorizationServerMetadata{
		Issuer:                                 P("/"),
		ServiceDocumentation:                   "https://pomerium.com/docs",
		AuthorizationEndpoint:                  P(path.Join(prefix, authorizationEndpoint)),
		ResponseTypesSupported:                 []string{"code"},
		CodeChallengeMethodsSupported:          []string{"S256"},
		TokenEndpoint:                          P(path.Join(prefix, tokenEndpoint)),
		TokenEndpointAuthMethodsSupported:      []string{"client_secret_basic", "none"},
		GrantTypesSupported:                    []string{"authorization_code", "refresh_token"},
		RevocationEndpoint:                     P(path.Join(prefix, revocationEndpoint)),
		RevocationEndpointAuthMethodsSupported: []string{"client_secret_post"},
		RegistrationEndpoint:                   P(path.Join(prefix, registerEndpoint)),
		ScopesSupported:                        []string{"openid", "offline"},
	}
}

func getProtectedResourceMetadata(r *http.Request, _ string) ProtectedResourceMetadata {
	return ProtectedResourceMetadata{
		Resource: (&url.URL{
			Scheme: "https",
			Host:   r.Host,
			Path:   strings.TrimPrefix(r.URL.Path, WellKnownProtectedResourceEndpoint),
		}).String(),
		ResourceName: "Pomerium",
		AuthorizationServers: []string{(&url.URL{
			Scheme: "https",
			Host:   r.Host,
		}).String()},
		ScopesSupported:        []string{"openid", "offline"},
		BearerMethodsSupported: []string{"header"},
	}
}

func getMetadataHandler[T any](fn func(r *http.Request, prefix string) T, prefix string) http.HandlerFunc {
	c := cors.New(cors.Options{
		AllowedMethods: []string{http.MethodGet, http.MethodOptions},
		AllowedOrigins: []string{"*"},
		AllowedHeaders: []string{"mcp-protocol-version"},
	})
	r := mux.NewRouter()
	r.Use(c.Handler)
	r.Methods(http.MethodGet).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		meta := fn(r, prefix)
		_ = json.NewEncoder(w).Encode(meta)
	})
	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(r.ServeHTTP)
}

func ProtectedResourceMetadataURL(host string) string {
	return (&url.URL{
		Scheme: "https",
		Host:   host,
		Path:   WellKnownProtectedResourceEndpoint,
	}).String()
}

func Set401WWWAuthenticateHeader(dst http.Header, host string) error {
	dict := sfv.Dictionary{
		{
			Key:  "error",
			Item: sfv.Item{Value: "invalid_request"},
		},
		{
			Key:  "error_description",
			Item: sfv.Item{Value: "No access token was provided in this request"},
		},
		{
			Key:  "resource_metadata",
			Item: sfv.Item{Value: ProtectedResourceMetadataURL(host)},
		},
	}
	txt, err := sfv.EncodeDictionary(dict)
	if err != nil {
		return err
	}
	dst.Set("www-authenticate", `Bearer `+txt)
	return nil
}
