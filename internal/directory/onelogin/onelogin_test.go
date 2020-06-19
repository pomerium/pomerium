package onelogin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/grpc/directory"
)

type M = map[string]interface{}

func newMockAPI(srv *httptest.Server, userEmailToGroupName map[string]string) http.Handler {
	lookup := map[string]struct{}{}
	for _, group := range userEmailToGroupName {
		lookup[group] = struct{}{}
	}
	var allGroups []string
	for groupName := range lookup {
		allGroups = append(allGroups, groupName)
	}
	sort.Strings(allGroups)

	var allEmails []string
	for email := range userEmailToGroupName {
		allEmails = append(allEmails, email)
	}
	sort.Strings(allEmails)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Post("/auth/oauth2/v2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "client_id:CLIENTID, client_secret:CLIENTSECRET" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		var request struct {
			GrantType string `json:"grant_type"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.GrantType != "client_credentials" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}

		_ = json.NewEncoder(w).Encode(M{
			"access_token":  "ACCESSTOKEN",
			"created_at":    time.Now().Format(time.RFC3339),
			"expires_in":    360000,
			"refresh_token": "REFRESHTOKEN",
			"token_type":    "bearer",
		})
	})
	r.Route("/api/1", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "bearer:ACCESSTOKEN" {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		})
		r.Get("/groups", func(w http.ResponseWriter, r *http.Request) {
			var result struct {
				Pagination struct {
					NextLink string `json:"next_link"`
				} `json:"pagination"`
				Data []M `json:"data"`
			}

			found := r.URL.Query().Get("after") == ""
			for i := range allGroups {
				if found {
					result.Data = append(result.Data, M{
						"id":   i,
						"name": allGroups[i],
					})
					break
				}
				found = r.URL.Query().Get("after") == fmt.Sprint(i)
			}

			if len(result.Data) > 0 {
				nextURL := mustParseURL(srv.URL).ResolveReference(r.URL)
				q := nextURL.Query()
				q.Set("after", fmt.Sprint(result.Data[0]["id"]))
				nextURL.RawQuery = q.Encode()
				result.Pagination.NextLink = nextURL.String()
			}

			_ = json.NewEncoder(w).Encode(result)
		})
		r.Get("/users", func(w http.ResponseWriter, r *http.Request) {
			userEmailToGroupID := map[string]int{}
			for email, groupName := range userEmailToGroupName {
				for id, n := range allGroups {
					if groupName == n {
						userEmailToGroupID[email] = id
					}
				}
			}

			var result []M
			for i, email := range allEmails {
				result = append(result, M{
					"id":       i,
					"email":    email,
					"group_id": userEmailToGroupID[email],
				})
			}
			_ = json.NewEncoder(w).Encode(M{
				"data": result,
			})
		})
	})
	return r
}

func TestProvider_UserGroups(t *testing.T) {
	var mockAPI http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockAPI.ServeHTTP(w, r)
	}))
	defer srv.Close()
	mockAPI = newMockAPI(srv, map[string]string{
		"a@example.com": "admin",
		"b@example.com": "test",
		"c@example.com": "user",
	})

	p := New(
		WithServiceAccount(&ServiceAccount{
			ClientID:     "CLIENTID",
			ClientSecret: "CLIENTSECRET",
		}),
		WithURL(mustParseURL(srv.URL)),
	)
	users, err := p.UserGroups(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []*directory.User{
		{
			Id:     "a@example.com",
			Groups: []string{"admin"},
		},
		{
			Id:     "b@example.com",
			Groups: []string{"test"},
		},
		{
			Id:     "c@example.com",
			Groups: []string{"user"},
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
