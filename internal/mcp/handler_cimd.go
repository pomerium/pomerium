package mcp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"

	"github.com/pomerium/pomerium/internal/log"
)

// clientMetadataEndpoint is the path (relative to DefaultPrefix) for Client ID Metadata Documents.
// Per draft-ietf-oauth-client-id-metadata-document, the client_id URL can be any HTTPS URL
// that returns the metadata document. We host it under the MCP prefix for consistency.
const clientMetadataEndpoint = "/client/metadata.json"

// ClientIDMetadata serves per-host Client ID Metadata Documents for MCP server routes
// using auto-discovery mode.
//
// The handler dynamically generates CIMD documents based on the request host.
// It returns 404 for:
//   - Hosts not configured as MCP servers
//   - Hosts with upstream_oauth2 configured (not auto-discovery mode)
//
// Per draft-ietf-oauth-client-id-metadata-document, the CIMD document includes:
//   - client_id: The URL of this document
//   - redirect_uris: The Pomerium client OAuth callback endpoint
//   - token_endpoint_auth_method: "none" (public client)
func (h *Handler) ClientIDMetadata(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	log.Ctx(ctx).Debug().
		Str("host", r.Host).
		Msg("mcp/cimd: request received")

	doc, ok := h.generateClientIDMetadata(r)
	if !ok {
		log.Ctx(ctx).Debug().
			Str("host", r.Host).
			Msg("mcp/cimd: host not eligible for auto-discovery CIMD")
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	log.Ctx(ctx).Debug().
		Str("host", r.Host).
		Str("client_id", doc.ClientID).
		Msg("mcp/cimd: serving CIMD document")

	w.Header().Set("Content-Type", "application/json")
	// Cache for 1 hour - CIMD is relatively static per route
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(doc)
}

// generateClientIDMetadata generates a CIMD document for the request host.
// Returns (nil, false) if the host is not eligible for auto-discovery.
func (h *Handler) generateClientIDMetadata(r *http.Request) (*ClientIDMetadataDocument, bool) {
	requestHost := r.Host
	if requestHost == "" {
		return nil, false
	}

	// Extract hostname without port for config lookup - HostInfo is keyed by hostname only
	hostname := requestHost
	if h, _, err := net.SplitHostPort(requestHost); err == nil {
		hostname = h
	}

	// Check if this host uses auto-discovery mode (no upstream_oauth2)
	if !h.hosts.UsesAutoDiscovery(hostname) {
		return nil, false
	}

	// Get server info for metadata - this validates the hostname against config
	serverInfo, ok := h.hosts.GetServerHostInfo(hostname)
	if !ok {
		return nil, false
	}

	// Use the full request host (including port) for URLs, but only after
	// validating the hostname against config. This approach:
	// - Prevents Host header injection (only configured hostnames are accepted)
	// - Ensures client_id URL matches the document's actual URL (including port)
	// - Is consistent with AS metadata which also uses r.Host
	validatedHost := requestHost

	// Build client_id URL (must match this document's URL exactly)
	clientIDURL := (&url.URL{
		Scheme: "https",
		Host:   validatedHost,
		Path:   path.Join(DefaultPrefix, clientMetadataEndpoint),
	}).String()

	// Build redirect URI for client OAuth callback
	redirectURI := (&url.URL{
		Scheme: "https",
		Host:   validatedHost,
		Path:   path.Join(DefaultPrefix, clientOAuthCallbackEndpoint),
	}).String()

	// Generate client name from hostname (use hostname without port for display)
	clientName := fmt.Sprintf("Pomerium MCP Proxy - %s", hostname)
	if serverInfo.Name != "" {
		clientName = serverInfo.Name
	}

	return &ClientIDMetadataDocument{
		ClientID:                clientIDURL,
		ClientName:              clientName,
		ClientURI:               "https://" + validatedHost,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}, true
}
