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
		AllowedUsers:                     []string{"user1", "user2"},
		AllowedIDPClaims: map[string][]any{
			"family_name": {"Smith", "Jones"},
		},
		SubPolicies: []SubPolicy{
			{
				AllowedDomains: []string{"c.example.com", "d.example.com"},
				AllowedUsers:   []string{"user3", "user4"},
				AllowedIDPClaims: map[string][]any{
					"given_name": {"John"},
				},
			},
			{
				AllowedDomains: []string{"e.example.com"},
				AllowedUsers:   []string{"user5"},
				AllowedIDPClaims: map[string][]any{
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

import rego.v1

default allow := [false, set()]

default deny := [false, set()]

accept_0 := [true, {"accept"}]

cors_preflight_0 := [true, {"cors-request"}] if {
	input.http.method == "OPTIONS"
	count(object.get(input.http.headers, "Access-Control-Request-Method", [])) > 0
	count(object.get(input.http.headers, "Origin", [])) > 0
}

else := [false, {"non-cors-request"}]

authenticated_user_0 := [true, {"user-ok"}] if {
	session := get_session(input.session.id)
	session.user_id != null
	session.user_id != ""
}

else := [false, {"user-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

domain_0 := [true, {"domain-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	domain := split(get_user_email(session, user, directory_user), "@")[1]
	domain == "a.example.com"
}

else := [false, {"domain-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

domain_1 := [true, {"domain-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	domain := split(get_user_email(session, user, directory_user), "@")[1]
	domain == "b.example.com"
}

else := [false, {"domain-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

domain_2 := [true, {"domain-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	domain := split(get_user_email(session, user, directory_user), "@")[1]
	domain == "c.example.com"
}

else := [false, {"domain-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

domain_3 := [true, {"domain-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	domain := split(get_user_email(session, user, directory_user), "@")[1]
	domain == "d.example.com"
}

else := [false, {"domain-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

domain_4 := [true, {"domain-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	domain := split(get_user_email(session, user, directory_user), "@")[1]
	domain == "e.example.com"
}

else := [false, {"domain-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

claim_0 := [true, {"claim-ok"}] if {
	rule_path := "family_name"
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	count([true | some v; v = values[_0]; v == "Smith"]) > 0
}

else := [false, {"claim-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

claim_1 := [true, {"claim-ok"}] if {
	rule_path := "family_name"
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	count([true | some v; v = values[_0]; v == "Jones"]) > 0
}

else := [false, {"claim-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

claim_2 := [true, {"claim-ok"}] if {
	rule_path := "given_name"
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	count([true | some v; v = values[_0]; v == "John"]) > 0
}

else := [false, {"claim-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

claim_3 := [true, {"claim-ok"}] if {
	rule_path := "timezone"
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	count([true | some v; v = values[_0]; v == "EST"]) > 0
}

else := [false, {"claim-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

user_0 := [true, {"user-ok"}] if {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user1"
}

else := [false, {"user-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

email_0 := [true, {"email-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	email := get_user_email(session, user, directory_user)
	email == "user1"
}

else := [false, {"email-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

user_1 := [true, {"user-ok"}] if {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user2"
}

else := [false, {"user-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

email_1 := [true, {"email-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	email := get_user_email(session, user, directory_user)
	email == "user2"
}

else := [false, {"email-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

user_2 := [true, {"user-ok"}] if {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user3"
}

else := [false, {"user-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

email_2 := [true, {"email-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	email := get_user_email(session, user, directory_user)
	email == "user3"
}

else := [false, {"email-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

user_3 := [true, {"user-ok"}] if {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user4"
}

else := [false, {"user-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

email_3 := [true, {"email-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	email := get_user_email(session, user, directory_user)
	email == "user4"
}

else := [false, {"email-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

user_4 := [true, {"user-ok"}] if {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user5"
}

else := [false, {"user-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

email_4 := [true, {"email-ok"}] if {
	session := get_session(input.session.id)
	user := get_user(session)
	directory_user := get_directory_user(session)
	email := get_user_email(session, user, directory_user)
	email == "user5"
}

else := [false, {"email-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

or_0 := v if {
	results := [accept_0, cors_preflight_0, authenticated_user_0, domain_0, domain_1, domain_2, domain_3, domain_4, claim_0, claim_1, claim_2, claim_3, user_0, email_0, user_1, email_1, user_2, email_2, user_3, email_3, user_4, email_4]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

user_5 := [true, {"user-ok"}] if {
	session := get_session(input.session.id)
	user_id := session.user_id
	user_id == "user6"
}

else := [false, {"user-unauthorized"}] if {
	session := get_session(input.session.id)
	session.id != ""
}

else := [false, {"user-unauthenticated"}]

or_1 := v if {
	results := [user_5]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

allow := v if {
	results := [or_0, or_1]
	normalized := [normalize_criterion_result(x) | x := results[i]]
	v := merge_with_or(normalized)
}

invert_criterion_result(v) := out if {
	v[0]
	out = array.concat([false], array.slice(v, 1, count(v)))
}

else := out if {
	not v[0]
	out = array.concat([true], array.slice(v, 1, count(v)))
}

normalize_criterion_result(result) := v if {
	is_boolean(result)
	v = [result, set()]
}

else := v if {
	is_array(result)
	v = result
}

else := v if {
	v = [false, set()]
}

object_union(xs) := merged if {
	merged = {k: v |
		some k
		xs[_0][k]
		vs := [xv | xv := xs[_][k]]
		v := vs[count(vs) - 1]
	}
}

merge_with_and(results) := [true, reasons, additional_data] if {
	true_results := [x | x := results[i]; x[0]]
	count(true_results) == count(results)
	reasons := union({x | x := true_results[i][1]})
	additional_data := object_union({x | x := true_results[i][2]})
}

else := [false, reasons, additional_data] if {
	false_results := [x | x := results[i]; not x[0]]
	reasons := union({x | x := false_results[i][1]})
	additional_data := object_union({x | x := false_results[i][2]})
}

merge_with_or(results) := [true, reasons, additional_data] if {
	true_results := [x | x := results[i]; x[0]]
	count(true_results) > 0
	reasons := union({x | x := true_results[i][1]})
	additional_data := object_union({x | x := true_results[i][2]})
}

else := [false, reasons, additional_data] if {
	false_results := [x | x := results[i]; not x[0]]
	reasons := union({x | x := false_results[i][1]})
	additional_data := object_union({x | x := false_results[i][2]})
}

get_session(id) := v if {
	v = get_databroker_record("type.googleapis.com/user.ServiceAccount", id)
	v != null
}

else := iv if {
	v = get_databroker_record("type.googleapis.com/session.Session", id)
	v != null
	object.get(v, "impersonate_session_id", "") != ""

	iv = get_databroker_record("type.googleapis.com/session.Session", v.impersonate_session_id)
	iv != null
}

else := v if {
	v = get_databroker_record("type.googleapis.com/session.Session", id)
	v != null
	object.get(v, "impersonate_session_id", "") == ""
}

else := {}

get_user(session) := v if {
	v = get_databroker_record("type.googleapis.com/user.User", session.user_id)
	v != null
}

else := {}

get_directory_user(session) := v if {
	v = get_databroker_record("pomerium.io/DirectoryUser", session.user_id)
	v != null
}

else := {}

get_user_email(session, user, directory_user) := v if {
	v = object.get(directory_user, "email", "")
	v != ""
}

else := v if {
	v = user.email
}

else := ""

object_get(obj, key, def) := value if {
	undefined := "10a0fd35-0f1a-4e5b-97ce-631e89e1bafa"
	value = object.get(obj, key, undefined)
	value != undefined
}

else := value if {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 2
	o1 := object.get(obj, segments[0], {})
	value = object.get(o1, segments[1], def)
}

else := value if {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 3
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	value = object.get(o2, segments[2], def)
}

else := value if {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 4
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	value = object.get(o3, segments[3], def)
}

else := value if {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 5
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	o4 := object.get(o3, segments[3], {})
	value = object.get(o4, segments[4], def)
}

else := value if {
	value = object.get(obj, key, def)
}
`, str)
}

func TestPolicy_ToPPL_Embedded(t *testing.T) {
	policy := Policy{
		Policy: &PPLPolicy{
			Policy: &parser.Policy{
				Rules: []parser.Rule{
					{
						Action: parser.ActionAllow,
						Or: []parser.Criterion{
							{
								Name: "foo",
								Data: parser.Number("5"),
							},
						},
					},
				},
			},
		},
	}
	assert.Equal(t, policy.Policy.Policy, policy.ToPPL())

	policy2 := Policy{
		AllowedUsers: []string{"test"},
		Policy: &PPLPolicy{
			Policy: &parser.Policy{
				Rules: []parser.Rule{
					{
						Action: parser.ActionAllow,
						Or: []parser.Criterion{
							{
								Name: "foo",
								Data: parser.Number("5"),
							},
						},
					},
				},
			},
		},
	}
	assert.Equal(t, &parser.Policy{
		Rules: []parser.Rule{
			{
				Action: parser.ActionAllow,
				Or: []parser.Criterion{
					{
						Name: "user",
						Data: parser.Object{
							"is": parser.String("test"),
						},
					},
					{
						Name: "email",
						Data: parser.Object{
							"is": parser.String("test"),
						},
					},
				},
			},
			{
				Action: parser.ActionAllow,
				Or: []parser.Criterion{
					{
						Name: "foo",
						Data: parser.Number("5"),
					},
				},
			},
		},
	}, policy2.ToPPL())
}

func TestUpstreamTunnelPPL(t *testing.T) {
	var p Policy
	assert.Nil(t, p.UpstreamTunnelPPL())
	p.UpstreamTunnel = &UpstreamTunnel{}
	assert.Nil(t, p.UpstreamTunnelPPL())
	p.UpstreamTunnel.SSHPolicy = &PPLPolicy{}
	assert.Nil(t, p.UpstreamTunnelPPL())
	ppl := parser.Policy{
		Rules: []parser.Rule{{
			Action: parser.ActionAllow,
			And: []parser.Criterion{{
				Name: "foo",
				Data: parser.String("bar"),
			}},
		}},
	}
	p.UpstreamTunnel.SSHPolicy.Policy = &ppl
	assert.Same(t, &ppl, p.UpstreamTunnelPPL())
}
