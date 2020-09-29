package azure

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
)

type (
	groupsDeltaCollection struct {
		provider  *Provider
		groups    map[string]groupsDeltaGroup
		deltaLink string
	}
	groupsDeltaGroup struct {
		id          string
		displayName string
		members     map[string]groupsDeltaGroupMember
	}
	groupsDeltaGroupMember struct {
		memberType  string
		id          string
		displayName string
		email       string
	}
)

func newGroupsDeltaCollection(p *Provider) *groupsDeltaCollection {
	return &groupsDeltaCollection{
		provider: p,
		groups:   make(map[string]groupsDeltaGroup),
	}
}

// Sync syncs the latest changes from the microsoft graph API.
//
// Synchronization is based on https://docs.microsoft.com/en-us/graph/delta-query-groups
//
// It involves 4 steps:
//
//   1. an initial request to /v1.0/groups/delta
//   2. one or more requests to /v1.0/groups/delta?$skiptoken=..., which comes from the @odata.nextLink
//   3. a final response with @odata.deltaLink
//   4. on the next call to sync, starting at @odata.deltaLink
//
// Only the changed groups/members are returned. Removed groups/members have an @removed property.
func (gdc *groupsDeltaCollection) Sync(ctx context.Context) error {
	apiURL := gdc.deltaLink

	// if no delta link is set yet, start the initial fill
	if apiURL == "" {
		apiURL = gdc.provider.cfg.graphURL.ResolveReference(&url.URL{
			Path: "/v1.0/groups/delta",
			RawQuery: url.Values{
				"$select": {"displayName,members"},
			}.Encode(),
		}).String()
	}

	for {
		var res groupsDeltaResponse
		err := gdc.provider.api(ctx, "GET", apiURL, nil, &res)
		if err != nil {
			return err
		}

		for _, g := range res.Value {
			// if removed exists, the group was deleted
			if g.Removed != nil {
				delete(gdc.groups, g.ID)
				continue
			}

			gdg := gdc.groups[g.ID]
			gdg.id = g.ID
			gdg.displayName = g.DisplayName
			if gdg.members == nil {
				gdg.members = make(map[string]groupsDeltaGroupMember)
			}
			for _, m := range g.Members {
				// if removed exists, the member was deleted
				if m.Removed != nil {
					delete(gdg.members, m.ID)
					continue
				}

				gdg.members[m.ID] = groupsDeltaGroupMember{
					memberType:  m.Type,
					id:          m.ID,
					displayName: m.DisplayName,
					email:       m.getEmail(),
				}
			}
			gdc.groups[g.ID] = gdg
		}

		switch {
		case res.NextLink != "":
			// when there's a next link we will query again
			apiURL = res.NextLink
		default:
			// once no next link is set anymore, we save the delta link and return
			gdc.deltaLink = res.DeltaLink
			return nil
		}
	}
}

// CurrentUserGroups returns the directory groups and users based on the current state.
func (gdc *groupsDeltaCollection) CurrentUserGroups() ([]*directory.Group, []*directory.User) {
	var groups []*directory.Group

	userLookup := map[string]groupsDeltaGroupMember{}
	groupLookup := newGroupLookup()
	for _, g := range gdc.groups {
		groups = append(groups, &directory.Group{
			Id:   g.id,
			Name: g.displayName,
		})
		var groupIDs, userIDs []string
		for _, m := range g.members {
			switch m.memberType {
			case "#microsoft.graph.group":
				groupIDs = append(groupIDs, m.id)
			case "#microsoft.graph.user":
				userIDs = append(userIDs, m.id)
				userLookup[m.id] = m
			}
		}
		groupLookup.addGroup(g.id, groupIDs, userIDs)
	}

	var users []*directory.User
	for _, u := range userLookup {
		users = append(users, &directory.User{
			Id:          databroker.GetUserID(Name, u.id),
			GroupIds:    groupLookup.getGroupIDsForUser(u.id),
			DisplayName: u.displayName,
			Email:       u.email,
		})
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].GetId() < users[j].GetId()
	})

	return groups, users
}

// API types for the microsoft graph API.
type (
	groupsDeltaResponse struct {
		Context   string                     `json:"@odata.context"`
		NextLink  string                     `json:"@odata.nextLink,omitempty"`
		DeltaLink string                     `json:"@odata.deltaLink,omitempty"`
		Value     []groupsDeltaResponseGroup `json:"value"`
	}
	groupsDeltaResponseGroup struct {
		ID          string                           `json:"id"`
		DisplayName string                           `json:"displayName"`
		Members     []groupsDeltaResponseGroupMember `json:"members@delta"`
		Removed     *groupsDeltaResponseRemoved      `json:"@removed,omitempty"`
	}
	groupsDeltaResponseGroupMember struct {
		Type              string                      `json:"@odata.type"`
		ID                string                      `json:"id"`
		Mail              string                      `json:"mail"`
		DisplayName       string                      `json:"displayName"`
		UserPrincipalName string                      `json:"userPrincipalName"`
		Removed           *groupsDeltaResponseRemoved `json:"@removed,omitempty"`
	}
	groupsDeltaResponseRemoved struct {
		Reason string `json:"reason"`
	}
)

func (obj groupsDeltaResponseGroupMember) getEmail() string {
	if obj.Mail != "" {
		return obj.Mail
	}

	// AD often doesn't have the email address returned, but we can parse it from the UPN

	// UPN looks like:
	// cdoxsey_pomerium.com#EXT#@cdoxseypomerium.onmicrosoft.com
	email := obj.UserPrincipalName
	if idx := strings.Index(email, "#EXT"); idx > 0 {
		email = email[:idx]
	}
	// find the last _ and replace it with @
	if idx := strings.LastIndex(email, "_"); idx > 0 {
		email = email[:idx] + "@" + email[idx+1:]
	}
	return email
}
