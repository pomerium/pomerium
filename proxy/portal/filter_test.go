package portal_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/proxy/portal"
)

func TestCheckRouteAccess(t *testing.T) {
	t.Parallel()

	u1 := portal.User{}
	u2 := portal.User{SessionID: "s2", UserID: "u2", Email: "u2@example.com", Groups: []string{"g2"}}

	for _, tc := range []struct {
		name  string
		user  portal.User
		route *config.Policy
	}{
		{"no ppl", u1, &config.Policy{}},
		{"allow_any_authenticated_user", u1, &config.Policy{AllowAnyAuthenticatedUser: true}},
		{"allowed_domains", u2, &config.Policy{AllowedDomains: []string{"not.example.com"}}},
		{"allowed_users", u2, &config.Policy{AllowedUsers: []string{"u3"}}},
		{"not conditionals", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"not": [{"accept": 1}]}}`)}},
		{"nor conditionals", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"nor": [{"accept": 1}]}}`)}},
		{"and conditionals", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"and": [{"accept": 1}, {"accept": 1}]}}`)}},
		{"authenticated_user", u1, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"authenticated_user": 1}]}}`)}},
		{"domain", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"domain": "not.example.com"}]}}`)}},
		{"email", u1, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"email": "u2@example.com"}]}}`)}},
		{"groups", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"groups": {"has": "g3"}}]}}`)}},
	} {
		assert.False(t, portal.CheckRouteAccess(tc.user, tc.route), "%s: should deny access for %v to %v",
			tc.name, tc.user, tc.route)
	}

	for _, tc := range []struct {
		name  string
		user  portal.User
		route *config.Policy
	}{
		{"allow_public_unauthenticated_access", u1, &config.Policy{AllowPublicUnauthenticatedAccess: true}},
		{"allow_any_authenticated_user", u2, &config.Policy{AllowAnyAuthenticatedUser: true}},
		{"allowed_domains", u2, &config.Policy{AllowedDomains: []string{"example.com"}}},
		{"allowed_users", u2, &config.Policy{AllowedUsers: []string{"u2"}}},
		{"and conditionals", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"and": [{"accept": 1}]}}`)}},
		{"or conditionals", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"reject": 1}, {"accept": 1}]}}`)}},
		{"authenticated_user", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"authenticated_user": 1}]}}`)}},
		{"domain", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"domain": "example.com"}]}}`)}},
		{"email", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"email": "u2@example.com"}]}}`)}},
		{"groups", u2, &config.Policy{Policy: mustParsePPL(t, `{"allow": {"or": [{"groups": {"has": "g2"}}]}}`)}},
	} {
		assert.True(t, portal.CheckRouteAccess(tc.user, tc.route), "%s: should grant access for %v to %v",
			tc.name, tc.user, tc.route)
	}
}

func mustParsePPL(t testing.TB, raw string) *config.PPLPolicy {
	ppl, err := parser.New().ParseJSON(strings.NewReader(raw))
	require.NoError(t, err)
	return &config.PPLPolicy{Policy: ppl}
}
