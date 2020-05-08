package pomerium.authz

import data.route_policies
import data.shared_key

default allow = false

# allow public
allow {
	route := first_allowed_route(input.url)
	route_policies[route].AllowPublicUnauthenticatedAccess == true
}

# allow cors preflight
allow {
	route := first_allowed_route(input.url)
	route_policies[route].CORSAllowPreflight == true
	input.method == "OPTIONS"
	count(object.get(input.headers, "Access-Control-Request-Method", [])) > 0
	count(object.get(input.headers, "Origin", [])) > 0
}


# allow by email
allow {
	route := first_allowed_route(input.url)
	token.payload.email = route_policies[route].allowed_users[_]
	token.valid
	count(deny)==0
}

# allow group
allow {
	route := first_allowed_route(input.url)
	some group
	token.payload.groups[group] == route_policies[route].allowed_groups[_]
	token.valid
	count(deny)==0
}

# allow by impersonate email
allow {
	route := first_allowed_route(input.url)
	token.payload.impersonate_email = route_policies[route].allowed_users[_]
	token.valid
	count(deny)==0
}

# allow by impersonate group
allow {
	route := first_allowed_route(input.url)
	some group
	token.payload.impersonate_groups[group] == route_policies[route].allowed_groups[_]
	token.valid
	count(deny)==0
}

# allow by domain
allow {
	route := first_allowed_route(input.url)
	some domain
	email_in_domain(token.payload.email, route_policies[route].allowed_domains[domain])
	token.valid
	count(deny)==0
}

# allow by impersonate domain
allow {
	route := first_allowed_route(input.url)
	some domain
	email_in_domain(token.payload.impersonate_email, route_policies[route].allowed_domains[domain])
	token.valid
	count(deny)==0
}
# allow pomerium urls
allow {
	contains(input.url, "/.pomerium/")
	not contains(input.url,"/.pomerium/admin")
}

# returns the first matching route
first_allowed_route(input_url) = route {
	route := [route | some route ; allowed_route(input.url, route_policies[route])][0]
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
		`(?:(http[s]?)://)?([^/]+)([^?#]*)`,
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

default expired = false

expired {
	now_seconds:=time.now_ns()/1e9
	[header, payload, _] := io.jwt.decode(input.user)
	payload.exp < now_seconds
}

deny["token is expired (exp)"]{
	expired
}

deny[sprintf("token has bad audience (aud): %s not in %+v",[input.host,payload.aud])]{
	[header, payload, _] := io.jwt.decode(input.user)
	not element_in_list(payload.aud,input.host)
}

# allow user is admin
allow {
	element_in_list(data.admins, token.payload.email)
	token.valid
	count(deny)==0
	contains(input.url,".pomerium/admin")
}


# deny non-admin users from accesing admin routes
deny["user is not admin"]{
	not element_in_list(data.admins, token.payload.email)
	contains(input.url,".pomerium/admin")
}

token = {"payload": payload, "valid": valid} {
	[valid, header, payload] := io.jwt.decode_verify(
		input.user, {
			"secret": shared_key,
			"aud": input.host,
		}
	)
}

user:=token.payload.user
email:=token.payload.email
groups:=token.payload.groups
signed_jwt:=io.jwt.encode_sign({"alg": "ES256"}, token.payload, data.signing_key)


element_in_list(list, elem) {
  list[_] = elem
}
