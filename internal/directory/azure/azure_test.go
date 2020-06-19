package azure

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

	"github.com/pomerium/pomerium/internal/grpc/directory"
)

type M = map[string]interface{}

func newMockAPI(t *testing.T, srv *httptest.Server) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Post("/DIRECTORY_ID/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "CLIENT_ID", r.FormValue("client_id"))
		assert.Equal(t, "CLIENT_SECRET", r.FormValue("client_secret"))
		assert.Equal(t, defaultLoginScope, r.FormValue("scope"))
		assert.Equal(t, defaultLoginGrantType, r.FormValue("grant_type"))

		_ = json.NewEncoder(w).Encode(M{
			"access_token":  "ACCESSTOKEN",
			"token_type":    "Bearer",
			"refresh_token": "REFRESHTOKEN",
		})
	})
	r.Route("/v1.0", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer ACCESSTOKEN" {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		})
		r.Get("/groups", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(M{
				"value": []M{
					{"id": "admin"},
					{"id": "test"},
				},
			})
		})
		r.Get("/groups/{group_name}/members", func(w http.ResponseWriter, r *http.Request) {
			members := map[string][]M{
				"admin": {
					{"id": "user-1"},
				},
				"test": {
					{"id": "user-2"},
					{"id": "user-3"},
				},
			}
			_ = json.NewEncoder(w).Encode(M{
				"value": members[chi.URLParam(r, "group_name")],
			})
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
		WithGraphURL(mustParseURL(srv.URL)),
		WithLoginURL(mustParseURL(srv.URL)),
		WithServiceAccount(&ServiceAccount{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			DirectoryID:  "DIRECTORY_ID",
		}),
	)
	users, err := p.UserGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []*directory.User{
		{
			Id:     "user-1",
			Groups: []string{"admin"},
		},
		{
			Id:     "user-2",
			Groups: []string{"test"},
		},
		{
			Id:     "user-3",
			Groups: []string{"test"},
		},
	}, users)
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}
