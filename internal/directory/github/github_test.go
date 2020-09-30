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
	r.Post("/graphql", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		_ = json.NewEncoder(w).Encode(M{
			"data": M{
				"organization": M{
					"teams": M{
						"totalCount": 3,
						"edges": []M{
							{"node": M{
								"id": 1,
							}},
							{"node": M{
								"id": 2,
							}},
							{"node": M{
								"id": 3,
							}},
						},
					},
				},
			},
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
	r.Get("/users/{user_id}", func(w http.ResponseWriter, r *http.Request) {
		users := map[string]apiUserObject{
			"user1": {Login: "user1", Name: "User 1", Email: "user1@example.com"},
			"user2": {Login: "user2", Name: "User 2", Email: "user2@example.com"},
			"user3": {Login: "user3", Name: "User 3", Email: "user3@example.com"},
			"user4": {Login: "user4", Name: "User 4", Email: "user4@example.com"},
		}
		userID := chi.URLParam(r, "user_id")
		json.NewEncoder(w).Encode(users[userID])
	})
	return r
}

func TestProvider_User(t *testing.T) {
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
	du, err := p.User(context.Background(), "github/user1")
	if !assert.NoError(t, err) {
		return
	}
	testutil.AssertProtoJSONEqual(t, `{
		"id": "github/user1",
		"groupIds": ["1", "2", "3"],
		"displayName": "User 1",
		"email": "user1@example.com"
	}`, du)
}

func TestProvider_UserGroups(t *testing.T) {
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
		{ "id": "github/user1", "groupIds": ["1", "2", "3"], "displayName": "User 1", "email": "user1@example.com" },
		{ "id": "github/user2", "groupIds": ["1", "3"], "displayName": "User 2", "email": "user2@example.com" },
		{ "id": "github/user3", "groupIds": ["3"], "displayName": "User 3", "email": "user3@example.com" },
		{ "id": "github/user4", "groupIds": ["4"], "displayName": "User 4", "email": "user4@example.com" }
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
