package github

import (
	"context"
	"encoding/json"
	"fmt"
)

const maxPageCount = 100

type (
	qlData struct {
		Organization *qlOrganization `json:"organization"`
	}
	qlMembersWithRoleConnection struct {
		Nodes    []qlUser   `json:"nodes"`
		PageInfo qlPageInfo `json:"pageInfo"`
	}
	qlOrganization struct {
		MembersWithRole *qlMembersWithRoleConnection `json:"membersWithRole"`
		Team            *qlTeam                      `json:"team"`
		Teams           *qlTeamConnection            `json:"teams"`
	}
	qlPageInfo struct {
		EndCursor   string `json:"endCursor"`
		HasNextPage bool   `json:"hasNextPage"`
	}
	qlResult struct {
		Data *qlData `json:"data"`
	}
	qlTeam struct {
		ID      string                  `json:"id"`
		Name    string                  `json:"name"`
		Slug    string                  `json:"slug"`
		Members *qlTeamMemberConnection `json:"members"`
	}
	qlTeamConnection struct {
		Edges    []qlTeamEdge `json:"edges"`
		PageInfo qlPageInfo   `json:"pageInfo"`
	}
	qlTeamEdge struct {
		Node qlTeam `json:"node"`
	}
	qlTeamMemberConnection struct {
		Edges    []qlTeamMemberEdge `json:"edges"`
		PageInfo qlPageInfo         `json:"pageInfo"`
	}
	qlTeamMemberEdge struct {
		Node qlUser `json:"node"`
	}
	qlUser struct {
		ID    string `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
)

func (p *Provider) listOrganizationMembers(ctx context.Context, orgSlug string) ([]qlUser, error) {
	var results []qlUser
	var cursor *string
	for {
		var res qlResult
		q := fmt.Sprintf(`query {
			organization(login:%s) {
				membersWithRole(first:%d, after:%s) {
					pageInfo {
						endCursor
						hasNextPage
					}
					nodes {
						id
						login
						name
						email
					}
				}
			}
		}`, encode(orgSlug), maxPageCount, encode(cursor))
		_, err := p.graphql(ctx, q, &res)
		if err != nil {
			return nil, err
		}

		results = append(results, res.Data.Organization.MembersWithRole.Nodes...)

		if !res.Data.Organization.MembersWithRole.PageInfo.HasNextPage {
			break
		}
		cursor = &res.Data.Organization.MembersWithRole.PageInfo.EndCursor
	}
	return results, nil
}

func (p *Provider) listOrganizationTeamsWithMemberIDs(ctx context.Context, orgSlug string) ([]teamWithMemberIDs, error) {
	var results []teamWithMemberIDs
	var pageInfos []qlPageInfo

	// first query all the teams with their members
	var cursor *string
	for {
		var res qlResult
		q := fmt.Sprintf(`query {
			organization(login:%s) {
				teams(first:%d, after:%s) {
					pageInfo {
						endCursor
						hasNextPage
					}
					edges {
						node {
							id
							name
							slug
							members(first:%d) {
								pageInfo {
									endCursor
									hasNextPage
								}
								edges {
									node {
										id
									}
								}
							}
						}
					}
				}
			}
		}`, encode(orgSlug), maxPageCount, encode(cursor), maxPageCount)
		_, err := p.graphql(ctx, q, &res)
		if err != nil {
			return nil, err
		}

		for _, teamEdge := range res.Data.Organization.Teams.Edges {
			var memberIDs []string
			for _, memberEdge := range teamEdge.Node.Members.Edges {
				memberIDs = append(memberIDs, memberEdge.Node.ID)
			}
			results = append(results, teamWithMemberIDs{
				ID:        teamEdge.Node.ID,
				Slug:      teamEdge.Node.Slug,
				Name:      teamEdge.Node.Name,
				MemberIDs: memberIDs,
			})
			pageInfos = append(pageInfos, teamEdge.Node.Members.PageInfo)
		}

		if !res.Data.Organization.Teams.PageInfo.HasNextPage {
			break
		}
		cursor = &res.Data.Organization.Teams.PageInfo.EndCursor
	}

	// it's possible we didn't get all the members if the initial query, so go through each team and
	// check the member pageInfo. If there are still remaining members, query those.
	for i, pageInfo := range pageInfos {
		if !pageInfo.HasNextPage {
			continue
		}

		cursor = &pageInfo.EndCursor
		for {
			var res qlResult
			q := fmt.Sprintf(`query {
				organization(login:%s) {
					team(slug:%s) {
						members(first:%d, after:%s) {
							pageInfo {
								endCursor
								hasNextPage
							}
							edges {
								node {
									id
								}
							}
						}
					}
				}
			}`, encode(orgSlug), encode(results[i].Slug), maxPageCount, encode(cursor))
			_, err := p.graphql(ctx, q, &res)
			if err != nil {
				return nil, err
			}

			for _, memberEdge := range res.Data.Organization.Team.Members.Edges {
				results[i].MemberIDs = append(results[i].MemberIDs, memberEdge.Node.ID)
			}

			if !res.Data.Organization.Team.Members.PageInfo.HasNextPage {
				break
			}
			cursor = &res.Data.Organization.Team.Members.PageInfo.EndCursor
		}
	}

	return results, nil
}

func (p *Provider) listUserOrganizationTeams(ctx context.Context, userSlug string, orgSlug string) ([]string, error) {
	// GitHub's Rest API doesn't have an easy way of querying this data, so we use the GraphQL API.

	var teamSlugs []string
	var cursor *string
	for {
		var res qlResult
		q := fmt.Sprintf(`query {
			organization(login:%s) {
				teams(first:%d, userLogins:[%s], after:%s) {
					pageInfo {
						endCursor
						hasNextPage
					}
					edges {
						node {
							id
							slug
						}
					}
				}
			}
		}`, encode(orgSlug), maxPageCount, encode(userSlug), encode(cursor))
		_, err := p.graphql(ctx, q, &res)
		if err != nil {
			return nil, err
		}

		for _, edge := range res.Data.Organization.Teams.Edges {
			teamSlugs = append(teamSlugs, edge.Node.Slug)
		}

		if !res.Data.Organization.Teams.PageInfo.HasNextPage {
			break
		}
		cursor = &res.Data.Organization.Teams.PageInfo.EndCursor
	}

	return teamSlugs, nil
}

func encode(obj interface{}) string {
	bs, _ := json.Marshal(obj)
	return string(bs)
}
