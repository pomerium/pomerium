package okta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomnomnom/linkheader"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

type M = map[string]interface{}

func newMockOkta(srv *httptest.Server, userEmailToGroups map[string][]string) http.Handler {
	getAllGroups := func() map[string]struct{} {
		allGroups := map[string]struct{}{}
		for _, groups := range userEmailToGroups {
			for _, group := range groups {
				allGroups[group] = struct{}{}
			}
		}
		return allGroups
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "SSWS APITOKEN" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/groups", func(r chi.Router) {
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				lastUpdated := strings.Contains(r.URL.Query().Get("filter"), "lastUpdated ")
				var groups []string
				for group := range getAllGroups() {
					if lastUpdated && group != "user-updated" {
						continue
					}
					if !lastUpdated && group == "user-updated" {
						continue
					}
					groups = append(groups, group)
				}
				sort.Strings(groups)

				var result []M

				found := r.URL.Query().Get("after") == ""
				for i := range groups {
					if found {
						result = append(result, M{
							"id": groups[i],
							"profile": M{
								"name": groups[i] + "-name",
							},
						})
						break
					}
					found = r.URL.Query().Get("after") == groups[i]
				}

				if len(result) > 0 {
					nextURL := mustParseURL(srv.URL).ResolveReference(r.URL)
					q := nextURL.Query()
					q.Set("after", result[0]["id"].(string))
					nextURL.RawQuery = q.Encode()
					w.Header().Set("Link", linkheader.Link{
						URL: nextURL.String(),
						Rel: "next",
					}.String())
				}

				_ = json.NewEncoder(w).Encode(result)
			})
			r.Get("/{group}/users", func(w http.ResponseWriter, r *http.Request) {
				group := chi.URLParam(r, "group")

				if _, ok := getAllGroups()[group]; !ok {
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(`{
						"errorCode": "E0000007",
						"errorSummary": "Not found: {0}",
						"errorLink": E0000007,
						"errorId": "sampleE7p0NECLNnSN5z_xLNT",
						"errorCauses": []
					}`))
					return
				}

				var result []M
				for email, groups := range userEmailToGroups {
					for _, g := range groups {
						if group == g {
							result = append(result, M{
								"id": email,
								"profile": M{
									"email":     email,
									"firstName": "first",
									"lastName":  "last",
								},
							})
						}
					}
				}
				sort.Slice(result, func(i, j int) bool {
					return result[i]["id"].(string) < result[j]["id"].(string)
				})

				_ = json.NewEncoder(w).Encode(result)
			})
		})
		r.Route("/users", func(r chi.Router) {
			r.Get("/{user_id}/groups", func(w http.ResponseWriter, r *http.Request) {
				var groups []apiGroupObject
				for _, nm := range userEmailToGroups[chi.URLParam(r, "user_id")] {
					obj := apiGroupObject{
						ID: nm,
					}
					obj.Profile.Name = nm
					groups = append(groups, obj)
				}
				_ = json.NewEncoder(w).Encode(groups)
			})
			r.Get("/{user_id}", func(w http.ResponseWriter, r *http.Request) {
				user := apiUserObject{
					ID: chi.URLParam(r, "user_id"),
				}
				user.Profile.Email = chi.URLParam(r, "user_id")
				user.Profile.FirstName = "first"
				user.Profile.LastName = "last"
				_ = json.NewEncoder(w).Encode(user)
			})
		})
	})
	return r
}

func TestProvider_User(t *testing.T) {
	var mockOkta http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockOkta.ServeHTTP(w, r)
	}))
	defer srv.Close()
	mockOkta = newMockOkta(srv, map[string][]string{
		"a@example.com": {"user", "admin"},
		"b@example.com": {"user", "test"},
		"c@example.com": {"user"},
	})

	p := New(
		WithServiceAccount(&ServiceAccount{APIKey: "APITOKEN"}),
		WithProviderURL(mustParseURL(srv.URL)),
	)
	user, err := p.User(context.Background(), "a@example.com", "")
	if !assert.NoError(t, err) {
		return
	}
	testutil.AssertProtoJSONEqual(t, `{
		"id": "a@example.com",
		"groupIds": ["admin","user"],
		"displayName": "first last",
		"email": "a@example.com"
	}`, user)
}

func TestProvider_UserGroups(t *testing.T) {
	var mockOkta http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockOkta.ServeHTTP(w, r)
	}))
	defer srv.Close()
	mockOkta = newMockOkta(srv, map[string][]string{
		"a@example.com": {"user", "admin"},
		"b@example.com": {"user", "test"},
		"c@example.com": {"user"},
	})

	p := New(
		WithServiceAccount(&ServiceAccount{APIKey: "APITOKEN"}),
		WithProviderURL(mustParseURL(srv.URL)),
	)
	groups, users, err := p.UserGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []*directory.User{
		{
			Id:          "a@example.com",
			GroupIds:    []string{"admin", "user"},
			DisplayName: "first last",
			Email:       "a@example.com",
		},
		{
			Id:          "b@example.com",
			GroupIds:    []string{"test", "user"},
			DisplayName: "first last",
			Email:       "b@example.com",
		},
		{
			Id:          "c@example.com",
			GroupIds:    []string{"user"},
			DisplayName: "first last",
			Email:       "c@example.com",
		},
	}, users)
	assert.Len(t, groups, 3)
}

func TestProvider_UserGroupsQueryUpdated(t *testing.T) {
	var mockOkta http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockOkta.ServeHTTP(w, r)
	}))
	defer srv.Close()
	userEmailToGroups := map[string][]string{
		"a@example.com":       {"user", "admin"},
		"b@example.com":       {"user", "test"},
		"c@example.com":       {"user"},
		"updated@example.com": {"user-updated"},
	}
	mockOkta = newMockOkta(srv, userEmailToGroups)

	p := New(
		WithServiceAccount(&ServiceAccount{APIKey: "APITOKEN"}),
		WithProviderURL(mustParseURL(srv.URL)),
	)
	groups, users, err := p.UserGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []*directory.User{
		{
			Id:          "a@example.com",
			GroupIds:    []string{"admin", "user"},
			DisplayName: "first last",
			Email:       "a@example.com",
		},
		{
			Id:          "b@example.com",
			GroupIds:    []string{"test", "user"},
			DisplayName: "first last",
			Email:       "b@example.com",
		},
		{
			Id:          "c@example.com",
			GroupIds:    []string{"user"},
			DisplayName: "first last",
			Email:       "c@example.com",
		},
	}, users)
	assert.Len(t, groups, 3)

	groups, users, err = p.UserGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []*directory.User{
		{
			Id:          "a@example.com",
			GroupIds:    []string{"admin", "user"},
			DisplayName: "first last",
			Email:       "a@example.com",
		},
		{
			Id:          "b@example.com",
			GroupIds:    []string{"test", "user"},
			DisplayName: "first last",
			Email:       "b@example.com",
		},
		{
			Id:          "c@example.com",
			GroupIds:    []string{"user"},
			DisplayName: "first last",
			Email:       "c@example.com",
		},
		{
			Id:          "updated@example.com",
			GroupIds:    []string{"user-updated"},
			DisplayName: "first last",
			Email:       "updated@example.com",
		},
	}, users)
	assert.Len(t, groups, 4)

	userEmailToGroups["b@example.com"] = []string{"user"}

	groups, users, err = p.UserGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []*directory.User{
		{
			Id:          "a@example.com",
			GroupIds:    []string{"admin", "user"},
			DisplayName: "first last",
			Email:       "a@example.com",
		},
		{
			Id:          "b@example.com",
			GroupIds:    []string{"user"},
			DisplayName: "first last",
			Email:       "b@example.com",
		},
		{
			Id:          "c@example.com",
			GroupIds:    []string{"user"},
			DisplayName: "first last",
			Email:       "c@example.com",
		},
		{
			Id:          "updated@example.com",
			GroupIds:    []string{"user-updated"},
			DisplayName: "first last",
			Email:       "updated@example.com",
		},
	}, users)
	assert.Len(t, groups, 3)
}

func mustParseURL(rawurl string) *url.URL {
	u, err := url.Parse(rawurl)
	if err != nil {
		panic(err)
	}
	return u
}

func TestParseServiceAccount(t *testing.T) {
	tests := []struct {
		name              string
		rawServiceAccount string
		apiKey            string
		wantErr           bool
	}{
		{"json", "ewogICAgImFwaV9rZXkiOiAiZm9vIgp9Cg==", "foo", false},
		{"value", "Zm9v", "foo", false},
		{"empty", "", "", true},
		{"invalid", "Zm9v---", "", true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseServiceAccount(tc.rawServiceAccount)
			require.True(t, (err != nil) == tc.wantErr)
			if tc.apiKey != "" {
				assert.Equal(t, tc.apiKey, got.APIKey)
			}
		})
	}
}
