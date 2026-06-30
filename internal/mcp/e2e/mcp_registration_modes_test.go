package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	mcphandler "github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func enableMCP(cfg *config.Config, dcr bool) {
	if cfg.Options.RuntimeFlags == nil {
		cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
	}
	cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
	cfg.Options.RuntimeFlags[config.RuntimeFlagMCPDynamicClientRegistration] = dcr
}

// clientRegistrar obtains an OAuth client usable against Pomerium's MCP
// authorization server. It returns the client_id and (for confidential clients)
// the client_secret. The authMethod is the requested token_endpoint_auth_method.
type clientRegistrar func(t *testing.T, authMethod string) (clientID, clientSecret string)

type registrationMode struct {
	// name is the subtest name.
	name string
	// dcr enables Dynamic Client Registration
	dcr bool
	// confidential indicates whether this mode can produce confidential clients
	// (with a client_secret). CIMD clients are always public, so confidential
	// subtests are skipped for it.
	confidential bool
}

// registrationModes is the standard matrix: downstream DCR enabled, and DCR
// disabled with clients registering via Client ID Metadata Documents.
var registrationModes = []registrationMode{
	{name: "dcr", dcr: true, confidential: true},
	{name: "cimd", dcr: false, confidential: false},
}

// newDCRRegistrar returns a clientRegistrar that registers clients via the
// downstream RFC 7591 /register endpoint advertised in the AS metadata.
func newDCRRegistrar(
	ctx context.Context,
	asMetadata *mcphandler.AuthorizationServerMetadata,
	newClient func() *http.Client,
	redirectURI string,
) clientRegistrar {
	return func(t *testing.T, authMethod string) (string, string) {
		t.Helper()
		require.NotEmpty(t, asMetadata.RegistrationEndpoint,
			"AS metadata must advertise a registration_endpoint when DCR is enabled")
		clientMetadata := map[string]any{
			"redirect_uris":              []string{redirectURI},
			"client_name":                "Matrix Test Client",
			"token_endpoint_auth_method": authMethod,
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
		}
		body, err := json.Marshal(clientMetadata)
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, asMetadata.RegistrationEndpoint, strings.NewReader(string(body)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := newClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var regResp map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))
		clientID, _ := regResp["client_id"].(string)
		clientSecret, _ := regResp["client_secret"].(string)
		require.NotEmpty(t, clientID, "expected client_id in registration response")
		return clientID, clientSecret
	}
}

// newCIMDRegistrar returns a clientRegistrar that hosts a unique Client ID
// Metadata Document for each call on the provided upstream and returns its URL
// as the client_id. CIMD clients are public, so the returned client_secret is
// always empty and confidential authMethods are not supported.
func newCIMDRegistrar(
	metadataUpstream upstreams.HTTPUpstream,
	metadataBaseURL string,
	redirectURI string,
) clientRegistrar {
	var counter atomic.Int64
	return func(t *testing.T, authMethod string) (string, string) {
		t.Helper()
		require.Equal(t, "none", authMethod,
			"CIMD clients are public; confidential auth methods are not supported")
		n := counter.Add(1)
		path := "/oauth/client-metadata-" + strconv.FormatInt(n, 10) + ".json"
		clientID := metadataBaseURL + path
		metadataUpstream.Handle(path, func(w http.ResponseWriter, _ *http.Request) {
			metadata := map[string]any{
				"client_id":                  clientID,
				"client_name":                "Matrix Test Client via CIMD",
				"client_uri":                 metadataBaseURL,
				"redirect_uris":              []string{redirectURI},
				"grant_types":                []string{"authorization_code", "refresh_token"},
				"response_types":             []string{"code"},
				"token_endpoint_auth_method": "none",
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=3600")
			_ = json.NewEncoder(w).Encode(metadata)
		})
		return clientID, ""
	}
}
