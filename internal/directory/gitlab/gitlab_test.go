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
				{"id": 1},
				{"id": 2},
			})
		})
		r.Get("/groups/{group_name}/members", func(w http.ResponseWriter, r *http.Request) {
			members := map[string][]M{
				"1": {
					{"id": 11},
				},
				"2": {
					{"id": 12},
					{"id": 13},
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
	users, err := p.UserGroups(context.Background())
	assert.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `[
		{ "id": "11", "groups": ["1"] },
		{ "id": "12", "groups": ["2"] },
		{ "id": "13", "groups": ["2"] }
	]`, users)
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}
