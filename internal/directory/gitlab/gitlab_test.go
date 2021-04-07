package gitlab

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
	r.Route("/api/v4", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Private-Token") != "PRIVATE_TOKEN" {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		})
		r.Get("/groups", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]M{
				{"id": 1, "name": "Group 1"},
				{"id": 2, "name": "Group 2"},
			})
		})
		r.Get("/groups/{group_name}/members", func(w http.ResponseWriter, r *http.Request) {
			members := map[string][]M{
				"1": {
					{"id": 11, "name": "User 1", "email": "user1@example.com"},
				},
				"2": {
					{"id": 12, "name": "User 2", "email": "user2@example.com"},
					{"id": 13, "name": "User 3", "email": "user3@example.com"},
				},
			}
			_ = json.NewEncoder(w).Encode(members[chi.URLParam(r, "group_name")])
		})
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
			PrivateToken: "PRIVATE_TOKEN",
		}),
	)
	groups, users, err := p.UserGroups(context.Background())
	assert.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `[
		{ "id": "11", "groupIds": ["1"], "displayName": "User 1", "email": "user1@example.com" },
		{ "id": "12", "groupIds": ["2"], "displayName": "User 2", "email": "user2@example.com" },
		{ "id": "13", "groupIds": ["2"], "displayName": "User 3", "email": "user3@example.com" }
	]`, users)
	testutil.AssertProtoJSONEqual(t, `[
		{ "id": "1", "name": "Group 1" },
		{ "id": "2", "name": "Group 2" }
	]`, groups)
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}
