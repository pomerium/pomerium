package authenticateflow_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

// TestJWTClaimHeadersPropagation verifies that claims supplied by the identity
// provider propagate end-to-end: through the login flow, into both the
// X-Pomerium-Claim-* request headers and the signed X-Pomerium-Jwt-Assertion
// header presented to the upstream.
func TestJWTClaimHeadersPropagation(t *testing.T) {
	env := testenv.New(t)

	// The IdP returns standard profile claims plus a few custom claims in the
	// id_token and userinfo response.
	env.Add(scenarios.NewIDP([]*scenarios.User{{
		Email:     "user@example.com",
		FirstName: "Test",
		LastName:  "User",
		Claims: map[string]any{
			"department": "engineering",
			"scope":      "session:role:analyst",
			"roles":      []string{"admin", "viewer"},
		},
	}}))

	// Forward a mix of standard and custom claims as headers. The same payload
	// also backs the signed assertion, so these claims appear there too.
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.JWTClaimsHeaders = config.NewJWTClaimHeaders(
			"email", "department", "scope", "roles",
		)
	}))

	// The upstream echoes the request headers it received back as JSON.
	up := upstreams.HTTP(nil)
	up.Handle("/headers", func(w http.ResponseWriter, r *http.Request) {
		hdrs := make(map[string]string, len(r.Header))
		for k := range r.Header {
			hdrs[strings.ToLower(k)] = r.Header.Get(k)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(hdrs)
	})
	passIdentityHeaders := true
	route := up.Route().
		From(env.SubdomainURL("claims")).
		To(values.Bind(up.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) {
			p.AllowAnyAuthenticatedUser = true
			p.PassIdentityHeaders = &passIdentityHeaders
		})
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	resp, err := up.Get(route,
		upstreams.AuthenticateAs("user@example.com"),
		upstreams.Path("/headers"))
	require.NoError(t, err)
	defer resp.Body.Close()

	var hdrs map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&hdrs))

	// Claims arrive as individual X-Pomerium-Claim-* headers. Standard and
	// custom claims are treated the same way, and a multi-valued claim is joined
	// into a single comma-separated string.
	assert.Equal(t, "user@example.com", hdrs["x-pomerium-claim-email"])
	assert.Equal(t, "engineering", hdrs["x-pomerium-claim-department"])
	assert.Equal(t, "session:role:analyst", hdrs["x-pomerium-claim-scope"])
	assert.Equal(t, "admin,viewer", hdrs["x-pomerium-claim-roles"])

	// The same claims are present in the signed assertion JWT.
	assertion := hdrs["x-pomerium-jwt-assertion"]
	require.NotEmpty(t, assertion, "missing assertion header")
	payload := decodeJWTPayload(t, assertion)

	assert.Equal(t, "user@example.com", payload["email"])
	assert.Equal(t, "engineering", payload["department"])
	assert.Equal(t, "session:role:analyst", payload["scope"])
	assert.Equal(t, "admin,viewer", payload["roles"])
}

// decodeJWTPayload decodes the (unverified) payload section of a compact JWS.
func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "unexpected JWT format")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}
