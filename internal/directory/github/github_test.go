package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/testutil"
)

type M = map[string]interface{}

func newMockAPI(t *testing.T, srv *httptest.Server) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !assert.Equal(t, "Basic YWJjOnh5eg==", r.Header.Get("Authorization")) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	r.Get("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]M{
			{"login": "org1"},
			{"login": "org2"},
		})
	})
	r.Get("/orgs/{org_id}/teams", func(w http.ResponseWriter, r *http.Request) {
		teams := map[string][]M{
			"org1": {
				{"slug": "team1", "id": 1},
				{"slug": "team2", "id": 2},
			},
			"org2": {
				{"slug": "team3", "id": 3},
				{"slug": "team4", "id": 4},
			},
		}
		orgID := chi.URLParam(r, "org_id")
		json.NewEncoder(w).Encode(teams[orgID])
	})
	r.Get("/orgs/{org_id}/teams/{team_id}/members", func(w http.ResponseWriter, r *http.Request) {
		members := map[string]map[string][]M{
			"org1": {
				"team1": {
					{"login": "user1"},
					{"login": "user2"},
				},
				"team2": {
					{"login": "user1"},
				},
			},
			"org2": {
				"team3": {
					{"login": "user1"},
					{"login": "user2"},
					{"login": "user3"},
				},
				"team4": {
					{"login": "user4"},
				},
			},
		}
		orgID := chi.URLParam(r, "org_id")
		teamID := chi.URLParam(r, "team_id")
		json.NewEncoder(w).Encode(members[orgID][teamID])
	})
	return r
}

func Test(t *testing.T) {
	var mockAPI http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockAPI.ServeHTTP(w, r)
	}))
	defer srv.Close()
	mockAPI = newMockAPI(t, srv)

	p := New(
		WithURL(mustParseURL(srv.URL)),
		WithServiceAccount(&ServiceAccount{
			Username:            "abc",
			PersonalAccessToken: "xyz",
		}),
	)
	groups, users, err := p.UserGroups(context.Background())
	assert.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `[
		{ "id": "github/user1", "groupIds": ["1", "2", "3"] },
		{ "id": "github/user2", "groupIds": ["1", "3"] },
		{ "id": "github/user3", "groupIds": ["3"] },
		{ "id": "github/user4", "groupIds": ["4"] }
	]`, users)
	testutil.AssertProtoJSONEqual(t, `[
		{ "id": "1", "name": "team1" },
		{ "id": "2", "name": "team2" },
		{ "id": "3", "name": "team3" },
		{ "id": "4", "name": "team4" }
	]`, groups)
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}
