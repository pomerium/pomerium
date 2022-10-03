package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/policy"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func TestPolicy_ToPPL(t *testing.T) {
	str, err := policy.GenerateRegoFromPolicy((&Policy{
		AllowPublicUnauthenticatedAccess: true,
		CORSAllowPreflight:               true,
		AllowAnyAuthenticatedUser:        true,
		AllowedDomains:                   []string{"a.example.com", "b.example.com"},
		AllowedGroups:                    []string{"group1", "group2"},
		AllowedUsers:                     []string{"user1", "user2"},
		AllowedIDPClaims: map[string][]interface{}{
			"family_name": {"Smith", "Jones"},
		},
		SubPolicies: []SubPolicy{
			{
				AllowedDomains: []string{"c.example.com", "d.example.com"},
				AllowedGroups:  []string{"group3", "group4"},
				AllowedUsers:   []string{"user3", "user4"},
				AllowedIDPClaims: map[string][]interface{}{
					"given_name": {"John"},
				},
			},
			{
				AllowedDomains: []string{"e.example.com"},
				AllowedGroups:  []string{"group5"},
				AllowedUsers:   []string{"user5"},
				AllowedIDPClaims: map[string][]interface{}{
					"timezone": {"EST"},
				},
			},
		},
		Policy: &PPLPolicy{
			Policy: &parser.Policy{
				Rules: []parser.Rule{{
					Action: parser.ActionAllow,
					Or: []parser.Criterion{{
						Name: "user",
						Data: parser.Object{
							"is": parser.String("user6"),
						},
					}},
				}},
			},
		},
	}).ToPPL())
	require.NoError(t, err)
	assert.Equal(t, `package pomerium.policy

default allow = [false, set()]

default deny = [false, set()]

pomerium_routes_0 = [true, {"pomerium-route"}] {
	contains(input.http.url, "/.pomerium/")
}

else = [false, {"non-pomerium-route"}] {
	true
}

accept_0 = [true, {"accept"}]

cors_preflight_0 = [true, {"cors-request"}] {
	input.http.method == "OPTIONS"
	count(object.get(input.http.headers, "Access-Control-Request-Method", [])) > 0
	count(object.get(input.http.headers, "Origin", [])) > 0
}

else = [false, {"non-cors-request"}] {
	true
}

authenticated_user_0 = [true, {"user-ok"}] {
	session := get_session(input.session.id)
	session.user_id != null
	session.user_id != ""
}

else = [false, {"user-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

domain_0 = [true, {"domain-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain == "a.example.com"
}

else = [false, {"domain-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

domain_1 = [true, {"domain-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain == "b.example.com"
}

else = [false, {"domain-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

domain_2 = [true, {"domain-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain == "c.example.com"
}

else = [false, {"domain-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

domain_3 = [true, {"domain-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain == "d.example.com"
}

else = [false, {"domain-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

domain_4 = [true, {"domain-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain == "e.example.com"
}

else = [false, {"domain-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

groups_0 = [true, {"groups-ok"}] {
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	count([true | some v; v = groups[_0]; v == "group1"]) > 0
}

else = [false, {"groups-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

groups_1 = [true, {"groups-ok"}] {
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	count([true | some v; v = groups[_0]; v == "group2"]) > 0
}

else = [false, {"groups-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

groups_2 = [true, {"groups-ok"}] {
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	count([true | some v; v = groups[_0]; v == "group3"]) > 0
}

else = [false, {"groups-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

groups_3 = [true, {"groups-ok"}] {
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	count([true | some v; v = groups[_0]; v == "group4"]) > 0
}

else = [false, {"groups-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

groups_4 = [true, {"groups-ok"}] {
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	count([true | some v; v = groups[_0]; v == "group5"]) > 0
}

else = [false, {"groups-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

claim_0 = [true, {"claim-ok"}] {
	rule_data := "Smith"
	rule_path := "family_name"
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	rule_data == values[_0]
}

else = [false, {"claim-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

claim_1 = [true, {"claim-ok"}] {
	rule_data := "Jones"
	rule_path := "family_name"
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	rule_data == values[_0]
}

else = [false, {"claim-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

claim_2 = [true, {"claim-ok"}] {
	rule_data := "John"
	rule_path := "given_name"
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	rule_data == values[_0]
}

else = [false, {"claim-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

claim_3 = [true, {"claim-ok"}] {
	rule_data := "EST"
	rule_path := "timezone"
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	rule_data == values[_0]
}

else = [false, {"claim-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

user_0 = [true, {"user-ok"}] {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user1"
}

else = [false, {"user-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

email_0 = [true, {"email-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email == "user1"
}

else = [false, {"email-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

user_1 = [true, {"user-ok"}] {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user2"
}

else = [false, {"user-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

email_1 = [true, {"email-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email == "user2"
}

else = [false, {"email-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

user_2 = [true, {"user-ok"}] {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user3"
}

else = [false, {"user-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

email_2 = [true, {"email-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email == "user3"
}

else = [false, {"email-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

user_3 = [true, {"user-ok"}] {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user4"
}

else = [false, {"user-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

email_3 = [true, {"email-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email == "user4"
}

else = [false, {"email-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

user_4 = [true, {"user-ok"}] {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user5"
}

else = [false, {"user-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

email_4 = [true, {"email-ok"}] {
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email == "user5"
}

else = [false, {"email-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

or_0 = v {
	results := [pomerium_routes_0, accept_0, cors_preflight_0, authenticated_user_0, domain_0, domain_1, domain_2, domain_3, domain_4, groups_0, groups_1, groups_2, groups_3, groups_4, claim_0, claim_1, claim_2, claim_3, user_0, email_0, user_1, email_1, user_2, email_2, user_3, email_3, user_4, email_4]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

user_5 = [true, {"user-ok"}] {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user6"
}

else = [false, {"user-unauthorized"}] {
	session := get_session(input.session.id)
	session.id != ""
}

else = [false, {"user-unauthenticated"}] {
	true
}

or_1 = v {
	results := [user_5]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

allow = v {
	results := [or_0, or_1]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

invalid_client_certificate_0 = [true, {"invalid-client-certificate"}] {
	is_boolean(input.is_valid_client_certificate)
	not input.is_valid_client_certificate
}

else = [false, {"valid-client-certificate-or-none-required"}] {
	true
}

or_2 = v {
	results := [invalid_client_certificate_0]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

deny = v {
	results := [or_2]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

invert_criterion_result(in) = out {
	in[0]
	out = array.concat([false], array.slice(in, 1, count(in)))
}

else = out {
	not in[0]
	out = array.concat([true], array.slice(in, 1, count(in)))
}

normalize_criterion_result(result) = v {
	is_boolean(result)
	v = [result, set()]
}

else = v {
	is_array(result)
	v = result
}

else = v {
	v = [false, set()]
}

object_union(xs) = merged {
	merged = {k: v |
		some k
		xs[_0][k]
		vs := [xv | xv := xs[_][k]]
		v := vs[count(vs) - 1]
	}
}

merge_with_and(results) = [true, reasons, additional_data] {
	true_results := [x | x := results[i]; x[0]]
	count(true_results) == count(results)
	reasons := union({x | x := true_results[i][1]})
	additional_data := object_union({x | x := true_results[i][2]})
}

else = [false, reasons, additional_data] {
	false_results := [x | x := results[i]; not x[0]]
	reasons := union({x | x := false_results[i][1]})
	additional_data := object_union({x | x := false_results[i][2]})
}

merge_with_or(results) = [true, reasons, additional_data] {
	true_results := [x | x := results[i]; x[0]]
	count(true_results) > 0
	reasons := union({x | x := true_results[i][1]})
	additional_data := object_union({x | x := true_results[i][2]})
}

else = [false, reasons, additional_data] {
	false_results := [x | x := results[i]; not x[0]]
	reasons := union({x | x := false_results[i][1]})
	additional_data := object_union({x | x := false_results[i][2]})
}

get_session(id) = v {
	v = get_databroker_record("type.googleapis.com/user.ServiceAccount", id)
	v != null
}

else = iv {
	v = get_databroker_record("type.googleapis.com/session.Session", id)
	v != null
	object.get(v, "impersonate_session_id", "") != ""

	iv = get_databroker_record("type.googleapis.com/session.Session", v.impersonate_session_id)
	iv != null
}

else = v {
	v = get_databroker_record("type.googleapis.com/session.Session", id)
	v != null
	object.get(v, "impersonate_session_id", "") == ""
}

else = {} {
	true
}

get_user(session) = v {
	v = get_databroker_record("type.googleapis.com/user.User", session.user_id)
	v != null
}

else = {} {
	true
}

get_directory_user(session) = v {
	v = get_databroker_record("type.googleapis.com/directory.User", session.user_id)
	v != null
}

else = "" {
	true
}

get_directory_group(id) = v {
	v = get_databroker_record("type.googleapis.com/directory.Group", id)
	v != null
}

else = {} {
	true
}

get_user_email(session, user) = v {
	v = user.email
}

else = "" {
	true
}

get_group_ids(session, directory_user) = v {
	v = directory_user.group_ids
	v != null
}

else = [] {
	true
}

object_get(obj, key, def) = value {
	undefined := "10a0fd35-0f1a-4e5b-97ce-631e89e1bafa"
	value = object.get(obj, key, undefined)
	value != undefined
}

else = value {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 2
	o1 := object.get(obj, segments[0], {})
	value = object.get(o1, segments[1], def)
}

else = value {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 3
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	value = object.get(o2, segments[2], def)
}

else = value {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 4
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	value = object.get(o3, segments[3], def)
}

else = value {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 5
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	o4 := object.get(o3, segments[3], {})
	value = object.get(o4, segments[4], def)
}

else = value {
	value = object.get(obj, key, def)
}
`, str)
}
