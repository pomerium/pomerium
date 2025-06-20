package mcp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
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

func AuthorizationServerMetadataHandler(prefix string) http.HandlerFunc {
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

		meta := getAuthorizationServerMetadata(r.Host, prefix)
		_ = json.NewEncoder(w).Encode(meta)
	})
	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(r.ServeHTTP)
}

func getAuthorizationServerMetadata(host, prefix string) AuthorizationServerMetadata {
	baseURL := url.URL{
		Scheme: "https",
		Host:   host,
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
