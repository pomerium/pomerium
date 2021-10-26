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
	"github.com/vektah/gqlparser/ast"
	"github.com/vektah/gqlparser/parser"

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

		q, err := parser.ParseQuery(&ast.Source{
			Input: body.Query,
		})
		if err != nil {
			panic(err)
		}

		result := qlResult{
			Data: &qlData{
				Organization: &qlOrganization{},
			},
		}
		handleMembersWithRole := func(orgSlug string, field *ast.Field) {
			membersWithRole := &qlMembersWithRoleConnection{}

			var cursor string
			for _, arg := range field.Arguments {
				if arg.Name == "after" {
					cursor = arg.Value.Raw
				}
			}

			switch cursor {
			case `null`:
				switch orgSlug {
				case "org1":
					membersWithRole.PageInfo = qlPageInfo{EndCursor: "TOKEN1", HasNextPage: true}
					membersWithRole.Nodes = []qlUser{
						{ID: "user1", Login: "user1", Name: "User 1", Email: "user1@example.com"},
						{ID: "user2", Login: "user2", Name: "User 2", Email: "user2@example.com"},
					}
				case "org2":
					membersWithRole.PageInfo = qlPageInfo{HasNextPage: false}
					membersWithRole.Nodes = []qlUser{
						{ID: "user4", Login: "user4", Name: "User 4", Email: "user4@example.com"},
					}
				default:
					t.Errorf("unexpected org slug: %s", orgSlug)
				}
			case `TOKEN1`:
				membersWithRole.PageInfo = qlPageInfo{HasNextPage: false}
				membersWithRole.Nodes = []qlUser{
					{ID: "user3", Login: "user3", Name: "User 3", Email: "user3@example.com"},
				}
			default:
				t.Errorf("unexpected cursor: %s", cursor)
			}

			result.Data.Organization.MembersWithRole = membersWithRole
		}
		handleTeamMembers := func(orgSlug, teamSlug string, field *ast.Field) {
			result.Data.Organization.Team.Members = &qlTeamMemberConnection{
				PageInfo: qlPageInfo{HasNextPage: false},
			}

			switch teamSlug {
			case "team3":
				result.Data.Organization.Team.Members.Edges = []qlTeamMemberEdge{
					{Node: qlUser{ID: "user3"}},
				}
			}
		}
		handleTeam := func(orgSlug string, field *ast.Field) {
			result.Data.Organization.Team = &qlTeam{}

			var teamSlug string
			for _, arg := range field.Arguments {
				if arg.Name == "slug" {
					teamSlug = arg.Value.Raw
				}
			}

			for _, selection := range field.SelectionSet {
				subField, ok := selection.(*ast.Field)
				if !ok {
					continue
				}

				switch subField.Name {
				case "members":
					handleTeamMembers(orgSlug, teamSlug, subField)
				}
			}
		}
		handleTeams := func(orgSlug string, field *ast.Field) {
			teams := &qlTeamConnection{}

			var cursor string
			var userLogin string
			for _, arg := range field.Arguments {
				if arg.Name == "after" {
					cursor = arg.Value.Raw
				}
				if arg.Name == "userLogins" {
					userLogin = arg.Value.Children[0].Value.Raw
				}
			}

			switch cursor {
			case `null`:
				switch orgSlug {
				case "org1":
					teams.PageInfo = qlPageInfo{HasNextPage: true, EndCursor: "TOKEN1"}
					teams.Edges = []qlTeamEdge{
						{Node: qlTeam{ID: "MDQ6VGVhbTE=", Slug: "team1", Name: "Team 1", Members: &qlTeamMemberConnection{
							PageInfo: qlPageInfo{HasNextPage: false},
							Edges: []qlTeamMemberEdge{
								{Node: qlUser{ID: "user1"}},
								{Node: qlUser{ID: "user2"}},
							},
						}}},
					}
				case "org2":
					teams.PageInfo = qlPageInfo{HasNextPage: false}
					teams.Edges = []qlTeamEdge{
						{Node: qlTeam{ID: "MDQ6VGVhbTM=", Slug: "team3", Name: "Team 3", Members: &qlTeamMemberConnection{
							PageInfo: qlPageInfo{HasNextPage: true, EndCursor: "TOKEN1"},
							Edges: []qlTeamMemberEdge{
								{Node: qlUser{ID: "user1"}},
								{Node: qlUser{ID: "user2"}},
							},
						}}},
					}
					if userLogin == "" || userLogin == "user4" {
						teams.Edges = append(teams.Edges, qlTeamEdge{
							Node: qlTeam{ID: "MDQ6VGVhbTQ=", Slug: "team4", Name: "Team 4", Members: &qlTeamMemberConnection{
								PageInfo: qlPageInfo{HasNextPage: false},
								Edges: []qlTeamMemberEdge{
									{Node: qlUser{ID: "user4"}},
								},
							}},
						})
					}
				default:
					t.Errorf("unexpected org slug: %s", orgSlug)
				}
			case "TOKEN1":
				teams.PageInfo = qlPageInfo{HasNextPage: false}
				teams.Edges = []qlTeamEdge{
					{Node: qlTeam{ID: "MDQ6VGVhbTI=", Slug: "team2", Name: "Team 2", Members: &qlTeamMemberConnection{
						PageInfo: qlPageInfo{HasNextPage: false},
						Edges: []qlTeamMemberEdge{
							{Node: qlUser{ID: "user1"}},
						},
					}}},
				}
			default:
				t.Errorf("unexpected cursor: %s", cursor)
			}

			result.Data.Organization.Teams = teams
		}
		handleOrganization := func(field *ast.Field) {
			var orgSlug string
			for _, arg := range field.Arguments {
				if arg.Name == "login" {
					orgSlug = arg.Value.Raw
				}
			}
			for _, orgSelection := range field.SelectionSet {
				orgField, ok := orgSelection.(*ast.Field)
				if !ok {
					continue
				}

				switch orgField.Name {
				case "teams":
					handleTeams(orgSlug, orgField)
				case "team":
					handleTeam(orgSlug, orgField)
				case "membersWithRole":
					handleMembersWithRole(orgSlug, orgField)
				}
			}
		}

		for _, operation := range q.Operations {
			for _, selection := range operation.SelectionSet {
				field, ok := selection.(*ast.Field)
				if !ok {
					continue
				}

				if field.Name != "organization" {
					continue
				}

				handleOrganization(field)
			}
		}

		_ = json.NewEncoder(w).Encode(result)
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
	du, err := p.User(context.Background(), "user1", "")
	if !assert.NoError(t, err) {
		return
	}
	testutil.AssertProtoJSONEqual(t, `{
		"id": "user1",
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
		{ "id": "user1", "groupIds": ["1", "2", "3"], "displayName": "User 1", "email": "user1@example.com" },
		{ "id": "user2", "groupIds": ["1", "3"], "displayName": "User 2", "email": "user2@example.com" },
		{ "id": "user3", "groupIds": ["3"], "displayName": "User 3", "email": "user3@example.com" },
		{ "id": "user4", "groupIds": ["4"], "displayName": "User 4", "email": "user4@example.com" }
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
