package ping

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
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
)

type M = map[string]interface{}

func newMockAPI(userIDToGroupIDs map[string][]string) http.Handler {
	lookup := map[string]struct{}{}
	for _, groups := range userIDToGroupIDs {
		for _, group := range groups {
			lookup[group] = struct{}{}
		}
	}
	var allGroups []string
	for groupID := range lookup {
		allGroups = append(allGroups, groupID)
	}
	sort.Strings(allGroups)

	var allUserIDs []string
	for userID := range userIDToGroupIDs {
		allUserIDs = append(allUserIDs, userID)
	}
	sort.Strings(allUserIDs)

	filterToUserIDs := map[string][]string{}
	for userID, groupIDs := range userIDToGroupIDs {
		for _, groupID := range groupIDs {
			filter := fmt.Sprintf(`memberOfGroups[id eq "%s"]`, groupID)
			filterToUserIDs[filter] = append(filterToUserIDs[filter], userID)
		}
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Post("/ENVIRONMENTID/as/token", func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != "CLIENTID" || p != "CLIENTSECRET" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		grantType := r.FormValue("grant_type")
		if grantType != "client_credentials" {
			http.Error(w, "invalid grant_type", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(M{
			"access_token":  "ACCESSTOKEN",
			"created_at":    time.Now().Format(time.RFC3339),
			"expires_in":    360000,
			"refresh_token": "REFRESHTOKEN",
			"token_type":    "bearer",
		})
	})
	r.Route("/v1/environments/ENVIRONMENTID", func(r chi.Router) {
		r.Get("/groups", func(w http.ResponseWriter, r *http.Request) {
			var apiGroups []apiGroup
			for _, id := range allGroups {
				apiGroups = append(apiGroups, apiGroup{
					ID:   id,
					Name: "Group " + id,
				})
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(M{
				"_embedded": M{
					"groups": apiGroups,
				},
			})
		})
		r.Route("/users", func(r chi.Router) {
			r.Get("/{user_id}", func(w http.ResponseWriter, r *http.Request) {
				userID := chi.URLParam(r, "user_id")
				groupIDs, ok := userIDToGroupIDs[userID]
				if !ok {
					http.NotFound(w, r)
					return
				}

				au := apiUser{
					ID:    userID,
					Email: userID + "@example.com",
					Name: apiUserName{
						Given:  "Given-" + userID,
						Middle: "Middle-" + userID,
						Family: "Family-" + userID,
					},
				}
				if r.URL.Query().Get("include") == "memberOfGroupIDs" {
					au.MemberOfGroupIDs = groupIDs
				}

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(au)
			})
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				filter := r.URL.Query().Get("filter")
				userIDs, ok := filterToUserIDs[filter]
				if !ok {
					http.Error(w, "expected filter", http.StatusBadRequest)
					return
				}

				var apiUsers []apiUser
				for _, id := range userIDs {
					apiUsers = append(apiUsers, apiUser{
						ID:    id,
						Email: id + "@example.com",
						Name: apiUserName{
							Given:  "Given-" + id,
							Middle: "Middle-" + id,
							Family: "Family-" + id,
						},
					})
				}

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(M{
					"_embedded": M{
						"users": apiUsers,
					},
				})
			})
		})
	})
	return r
}

func TestProvider_User(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	srv := httptest.NewServer(newMockAPI(map[string][]string{
		"user1": {"group1", "group2"},
		"user2": {"group1", "group3"},
		"user3": {"group3"},
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	p := New(
		WithAPIURL(u),
		WithAuthURL(u),
		WithEnvironmentID("ENVIRONMENTID"),
		WithServiceAccount(&ServiceAccount{
			ClientID:     "CLIENTID",
			ClientSecret: "CLIENTSECRET",
		}))
	du, err := p.User(ctx, "user1", "")
	require.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `{
		"id": "user1",
		"email": "user1@example.com",
		"displayName": "Given-user1 Middle-user1 Family-user1",
		"groupIds": ["group1", "group2"]
	}`, du)
}

func TestProvider_UserGroups(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	srv := httptest.NewServer(newMockAPI(map[string][]string{
		"user1": {"group1", "group2"},
		"user2": {"group1", "group3"},
		"user3": {"group3"},
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	p := New(
		WithAPIURL(u),
		WithAuthURL(u),
		WithEnvironmentID("ENVIRONMENTID"),
		WithServiceAccount(&ServiceAccount{
			ClientID:     "CLIENTID",
			ClientSecret: "CLIENTSECRET",
		}))
	dgs, dus, err := p.UserGroups(ctx)
	require.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `[
		{ "id": "group1", "name": "Group group1" },
		{ "id": "group2", "name": "Group group2" },
		{ "id": "group3", "name": "Group group3" }
	]`, dgs)
	testutil.AssertProtoJSONEqual(t, `[
		{
		  "id": "user1",
		  "email": "user1@example.com",
		  "displayName": "Given-user1 Middle-user1 Family-user1",
		  "groupIds": ["group1", "group2"]
		},
		{
		  "id": "user2",
		  "email": "user2@example.com",
		  "displayName": "Given-user2 Middle-user2 Family-user2",
		  "groupIds": ["group1", "group3"]
		},
		{
		  "id": "user3",
		  "email": "user3@example.com",
		  "displayName": "Given-user3 Middle-user3 Family-user3",
		  "groupIds": ["group3"]
		}
	]`, dus)
}
