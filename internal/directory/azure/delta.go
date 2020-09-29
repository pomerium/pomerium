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
	deltaCollection struct {
		provider       *Provider
		groups         map[string]deltaGroup
		groupDeltaLink string
		users          map[string]deltaUser
		userDeltaLink  string
	}
	deltaGroup struct {
		id          string
		displayName string
		members     map[string]deltaGroupMember
	}
	deltaGroupMember struct {
		memberType string
		id         string
	}
	deltaUser struct {
		id          string
		displayName string
		email       string
	}
)

func newDeltaCollection(p *Provider) *deltaCollection {
	return &deltaCollection{
		provider: p,
		groups:   make(map[string]deltaGroup),
		users:    make(map[string]deltaUser),
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
func (dc *deltaCollection) Sync(ctx context.Context) error {
	if err := dc.syncGroups(ctx); err != nil {
		return err
	}

	if err := dc.syncUsers(ctx); err != nil {
		return err
	}

	return nil
}

func (dc *deltaCollection) syncGroups(ctx context.Context) error {
	apiURL := dc.groupDeltaLink

	// if no delta link is set yet, start the initial fill
	if apiURL == "" {
		apiURL = dc.provider.cfg.graphURL.ResolveReference(&url.URL{
			Path: "/v1.0/groups/delta",
			RawQuery: url.Values{
				"$select": {"displayName,members"},
			}.Encode(),
		}).String()
	}

	for {
		var res groupsDeltaResponse
		err := dc.provider.api(ctx, "GET", apiURL, nil, &res)
		if err != nil {
			return err
		}

		for _, g := range res.Value {
			// if removed exists, the group was deleted
			if g.Removed != nil {
				delete(dc.groups, g.ID)
				continue
			}

			gdg := dc.groups[g.ID]
			gdg.id = g.ID
			gdg.displayName = g.DisplayName
			if gdg.members == nil {
				gdg.members = make(map[string]deltaGroupMember)
			}
			for _, m := range g.Members {
				// if removed exists, the member was deleted
				if m.Removed != nil {
					delete(gdg.members, m.ID)
					continue
				}

				gdg.members[m.ID] = deltaGroupMember{
					memberType: m.Type,
					id:         m.ID,
				}
			}
			dc.groups[g.ID] = gdg
		}

		switch {
		case res.NextLink != "":
			// when there's a next link we will query again
			apiURL = res.NextLink
		default:
			// once no next link is set anymore, we save the delta link and return
			dc.groupDeltaLink = res.DeltaLink
			return nil
		}
	}
}

func (dc *deltaCollection) syncUsers(ctx context.Context) error {
	apiURL := dc.userDeltaLink

	// if no delta link is set yet, start the initial fill
	if apiURL == "" {
		apiURL = dc.provider.cfg.graphURL.ResolveReference(&url.URL{
			Path: "/v1.0/users/delta",
			RawQuery: url.Values{
				"$select": {"displayName,mail,userPrincipalName"},
			}.Encode(),
		}).String()
	}

	for {
		var res usersDeltaResponse
		err := dc.provider.api(ctx, "GET", apiURL, nil, &res)
		if err != nil {
			return err
		}

		for _, u := range res.Value {
			// if removed exists, the user was deleted
			if u.Removed != nil {
				delete(dc.users, u.ID)
				continue
			}
			dc.users[u.ID] = deltaUser{
				id:          u.ID,
				displayName: u.DisplayName,
				email:       u.getEmail(),
			}
		}

		switch {
		case res.NextLink != "":
			// when there's a next link we will query again
			apiURL = res.NextLink
		default:
			// once no next link is set anymore, we save the delta link and return
			dc.userDeltaLink = res.DeltaLink
			return nil
		}
	}
}

// CurrentUserGroups returns the directory groups and users based on the current state.
func (dc *deltaCollection) CurrentUserGroups() ([]*directory.Group, []*directory.User) {
	var groups []*directory.Group

	groupLookup := newGroupLookup()
	for _, g := range dc.groups {
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
			}
		}
		groupLookup.addGroup(g.id, groupIDs, userIDs)
	}

	var users []*directory.User
	for _, u := range dc.users {
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
	deltaResponseRemoved struct {
		Reason string `json:"reason"`
	}

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
		Removed     *deltaResponseRemoved            `json:"@removed,omitempty"`
	}
	groupsDeltaResponseGroupMember struct {
		Type    string                `json:"@odata.type"`
		ID      string                `json:"id"`
		Removed *deltaResponseRemoved `json:"@removed,omitempty"`
	}

	usersDeltaResponse struct {
		Context   string                   `json:"@odata.context"`
		NextLink  string                   `json:"@odata.nextLink,omitempty"`
		DeltaLink string                   `json:"@odata.deltaLink,omitempty"`
		Value     []usersDeltaResponseUser `json:"value"`
	}
	usersDeltaResponseUser struct {
		ID                string                `json:"id"`
		DisplayName       string                `json:"displayName"`
		Mail              string                `json:"mail"`
		UserPrincipalName string                `json:"userPrincipalName"`
		Removed           *deltaResponseRemoved `json:"@removed,omitempty"`
	}
)

func (obj usersDeltaResponseUser) getEmail() string {
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
