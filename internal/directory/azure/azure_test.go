package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/grpc/directory"
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
					{"id": "admin", "displayName": "Admin Group"},
					{"id": "test", "displayName": "Test Group"},
				},
			})
		})
		r.Get("/groups/{group_name}/members", func(w http.ResponseWriter, r *http.Request) {
			members := map[string][]M{
				"admin": {
					{"@odata.type": "#microsoft.graph.user", "id": "user-1"},
				},
				"test": {
					{"@odata.type": "#microsoft.graph.user", "id": "user-2"},
					{"@odata.type": "#microsoft.graph.user", "id": "user-3"},
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
	groups, users, err := p.UserGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []*directory.User{
		{
			Id:       "azure/user-1",
			GroupIds: []string{"admin"},
		},
		{
			Id:       "azure/user-2",
			GroupIds: []string{"test"},
		},
		{
			Id:       "azure/user-3",
			GroupIds: []string{"test"},
		},
	}, users)
	assert.Equal(t, []*directory.Group{
		{Id: "admin", Name: "Admin Group"},
		{Id: "test", Name: "Test Group"},
	}, groups)
}

func TestParseServiceAccount(t *testing.T) {
	t.Run("by options", func(t *testing.T) {
		serviceAccount, err := ParseServiceAccount(directory.Options{
			ProviderURL:  "https://login.microsoftonline.com/0303f438-3c5c-4190-9854-08d3eb31bd9f/v2.0",
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
		})
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, &ServiceAccount{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			DirectoryID:  "0303f438-3c5c-4190-9854-08d3eb31bd9f",
		}, serviceAccount)
	})
	t.Run("by service account", func(t *testing.T) {
		serviceAccount, err := ParseServiceAccount(directory.Options{
			ServiceAccount: base64.StdEncoding.EncodeToString([]byte(`{
				"client_id": "CLIENT_ID",
				"client_secret": "CLIENT_SECRET",
				"directory_id": "0303f438-3c5c-4190-9854-08d3eb31bd9f"
			}`)),
		})
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, &ServiceAccount{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			DirectoryID:  "0303f438-3c5c-4190-9854-08d3eb31bd9f",
		}, serviceAccount)
	})
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}
