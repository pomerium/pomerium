package pomerium.authz

default allow = false


route_policy_idx := first_allowed_route_policy_idx(input.http.url)
route_policy := data.route_policies[route_policy_idx]
session := input.databroker_data.session
user := input.databroker_data.user
groups := input.databroker_data.groups

all_allowed_domains := get_allowed_domains(route_policy)
all_allowed_groups := get_allowed_groups(route_policy)
all_allowed_users := get_allowed_users(route_policy)
all_allowed_idp_claims := get_allowed_idp_claims(route_policy)

# allow public
allow {
	route_policy.AllowPublicUnauthenticatedAccess == true
}

# allow cors preflight
allow {
	route_policy.CORSAllowPreflight == true
	input.http.method == "OPTIONS"
	count(object.get(input.http.headers, "Access-Control-Request-Method", [])) > 0
	count(object.get(input.http.headers, "Origin", [])) > 0
}

# allow any authenticated user
allow {
    route_policy.AllowAnyAuthenticatedUser == true
    session.user_id != ""
}

# allow by email
allow {
	user.email == all_allowed_users[_]
	input.session.impersonate_email == ""
}

# allow group
allow {
	some group
	groups[_] = group
	all_allowed_groups[_] = group
	input.session.impersonate_groups == null
}

# allow by impersonate email
allow {
	all_allowed_users[_] = input.session.impersonate_email
}

# allow by impersonate group
allow {
	some group
	input.session.impersonate_groups[_] = group
	all_allowed_groups[_] = group
}

# allow by domain
allow {
	some domain
	email_in_domain(user.email, all_allowed_domains[domain])
	input.session.impersonate_email == ""
}

# allow by impersonate domain
allow {
	some domain
	email_in_domain(input.session.impersonate_email, all_allowed_domains[domain])
}

# allow by arbitrary idp claims
allow {
    are_claims_allowed(all_allowed_idp_claims[_], session.claims)
}
allow {
    are_claims_allowed(all_allowed_idp_claims[_], user.claims)
}

# allow pomerium urls
allow {
	contains(input.http.url, "/.pomerium/")
	not contains(input.http.url, "/.pomerium/admin")
}

# allow user is admin
allow {
	element_in_list(data.admins, user.email)
	contains(input.http.url, ".pomerium/admin")
}

# deny non-admin users from accesing admin routes
deny[reason] {
	reason = [403, "user is not admin"]
	not element_in_list(data.admins, user.email)
	contains(input.http.url,".pomerium/admin")
}

deny[reason] {
	reason = [495, "invalid client certificate"]
	is_boolean(input.is_valid_client_certificate)
	not input.is_valid_client_certificate
}

# returns the first matching route
first_allowed_route_policy_idx(input_url) = first_policy_idx {
	first_policy_idx := [idx | some idx, policy; policy = data.route_policies[idx]; allowed_route(input.http.url, policy)][0]
}

allowed_route(input_url, policy){
	input_url_obj := parse_url(input_url)
	allowed_route_source(input_url_obj, policy)
	allowed_route_prefix(input_url_obj, policy)
	allowed_route_path(input_url_obj, policy)
	allowed_route_regex(input_url_obj, policy)
}

allowed_route_source(input_url_obj, policy) {
	object.get(policy, "source", "") == ""
}
allowed_route_source(input_url_obj, policy) {
	object.get(policy, "source", "") != ""
	source_url_obj := parse_url(policy.source)
	input_url_obj.host == source_url_obj.host
}

allowed_route_prefix(input_url_obj, policy) {
	object.get(policy, "prefix", "") == ""
}
allowed_route_prefix(input_url_obj, policy) {
	object.get(policy, "prefix", "") != ""
	startswith(input_url_obj.path, policy.prefix)
}

allowed_route_path(input_url_obj, policy) {
	object.get(policy, "path", "") == ""
}
allowed_route_path(input_url_obj, policy) {
	object.get(policy, "path", "") != ""
	policy.path == input_url_obj.path
}

allowed_route_regex(input_url_obj, policy) {
	object.get(policy, "regex", "") == ""
}
allowed_route_regex(input_url_obj, policy) {
	object.get(policy, "regex", "") != ""
	re_match(policy.regex, input_url_obj.path)
}

parse_url(str) = { "scheme": scheme, "host": host, "path": path } {
	[_, scheme, host, rawpath] = regex.find_all_string_submatch_n(
		`(?:((?:tcp[+])?http[s]?)://)?([^/]+)([^?#]*)`,
		str, 1)[0]
	path = normalize_url_path(rawpath)
}

normalize_url_path(str) = "/" {
	str == ""
}
normalize_url_path(str) = str {
	str != ""
}

email_in_domain(email, domain) {
	x := split(email, "@")
	count(x) == 2
	x[1] == domain
}

element_in_list(list, elem) {
  list[_] = elem
}

get_allowed_users(policy) = v {
    sub_allowed_users = [sp.allowed_users | sp := policy.sub_policies[_]]
    v := { x | x = array.concat(
        policy.allowed_users,
        [u | u := policy.sub_policies[_].allowed_users[_]]
    )[_] }
}

get_allowed_domains(policy) = v {
    v := { x | x = array.concat(
        policy.allowed_domains,
        [u | u := policy.sub_policies[_].allowed_domains[_]]
    )[_] }
}

get_allowed_groups(policy) = v {
    v := { x | x = array.concat(
        policy.allowed_groups,
        [u | u := policy.sub_policies[_].allowed_groups[_]]
    )[_] }
}

get_allowed_idp_claims(policy) = v {
    v := array.concat(
        [policy.allowed_idp_claims],
        [u | u := policy.sub_policies[_].allowed_idp_claims]
     )
}

are_claims_allowed(a, b) {
    is_object(a)
    is_object(b)
    avs := a[ak]
    bvs := object.get(b, ak, null)

    is_array(avs)
    is_array(bvs)
    avs[_] == bvs[_]
}
