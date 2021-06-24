package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/testutil"
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
		r.Get("/groups/delta", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(M{
				"value": []M{
					{
						"id":          "admin",
						"displayName": "Admin Group",
						"members@delta": []M{
							{"@odata.type": "#microsoft.graph.user", "id": "user-1"},
						},
					},
					{
						"id":          "test",
						"displayName": "Test Group",
						"members@delta": []M{
							{"@odata.type": "#microsoft.graph.user", "id": "user-2"},
							{"@odata.type": "#microsoft.graph.user", "id": "user-3"},
						},
					},
				},
			})
		})
		r.Get("/users/delta", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(M{
				"value": []M{
					{"id": "user-1", "displayName": "User 1", "mail": "user1@example.com"},
					{"id": "user-2", "displayName": "User 2", "mail": "user2@example.com"},
					{"id": "user-3", "displayName": "User 3", "userPrincipalName": "user3_example.com#EXT#@user3example.onmicrosoft.com"},
				},
			})
		})
		r.Get("/users/{user_id}", func(w http.ResponseWriter, r *http.Request) {
			switch chi.URLParam(r, "user_id") {
			case "user-1":
				_ = json.NewEncoder(w).Encode(M{"id": "user-1", "displayName": "User 1", "mail": "user1@example.com"})
			default:
				http.Error(w, "not found", http.StatusNotFound)
			}
		})
		r.Get("/users/{user_id}/transitiveMemberOf", func(w http.ResponseWriter, r *http.Request) {
			switch chi.URLParam(r, "user_id") {
			case "user-1":
				switch r.URL.Query().Get("page") {
				case "":
					_ = json.NewEncoder(w).Encode(M{
						"value": []M{
							{"id": "admin"},
						},
						"@odata.nextLink": getPageURL(r, 1),
					})
				case "1":
					_ = json.NewEncoder(w).Encode(M{
						"value": []M{
							{"id": "group1"},
						},
						"@odata.nextLink": getPageURL(r, 2),
					})
				case "2":
					_ = json.NewEncoder(w).Encode(M{
						"value": []M{
							{"id": "group2"},
						},
					})
				}
			default:
				http.Error(w, "not found", http.StatusNotFound)
			}
		})
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
		WithGraphURL(mustParseURL(srv.URL)),
		WithLoginURL(mustParseURL(srv.URL)),
		WithServiceAccount(&ServiceAccount{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			DirectoryID:  "DIRECTORY_ID",
		}),
	)

	du, err := p.User(context.Background(), "user-1", "")
	if !assert.NoError(t, err) {
		return
	}
	testutil.AssertProtoJSONEqual(t, `{
		"id": "user-1",
		"displayName": "User 1",
		"email": "user1@example.com",
		"groupIds": ["admin", "group1", "group2"]
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
			Id:          "user-1",
			GroupIds:    []string{"admin"},
			DisplayName: "User 1",
			Email:       "user1@example.com",
		},
		{
			Id:          "user-2",
			GroupIds:    []string{"test"},
			DisplayName: "User 2",
			Email:       "user2@example.com",
		},
		{
			Id:          "user-3",
			GroupIds:    []string{"test"},
			DisplayName: "User 3",
			Email:       "user3@example.com",
		},
	}, users)
	testutil.AssertProtoJSONEqual(t, `[
		{ "id": "admin", "name": "Admin Group" },
		{ "id": "test", "name": "Test Group"}
	]`, groups)
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

func getPageURL(r *http.Request, page int) string {
	var u url.URL
	u = *r.URL
	if r.TLS == nil {
		u.Scheme = "http"
	} else {
		u.Scheme = "https"
	}
	if u.Host == "" {
		u.Host = r.Host
	}
	q := u.Query()
	q.Set("page", strconv.Itoa(page))
	u.RawQuery = q.Encode()
	return u.String()
}
