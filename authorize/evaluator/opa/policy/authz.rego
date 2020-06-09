package pomerium.authz

default allow = false

directory_user_data := object.get(input.databroker_data, "type.googleapis.com/directory.User", {})

# allow public
allow {
	route := first_allowed_route(input.http.url)
	data.route_policies[route].AllowPublicUnauthenticatedAccess == true
}

# allow cors preflight
allow {
	route := first_allowed_route(input.http.url)
	data.route_policies[route].CORSAllowPreflight == true
	input.http.method == "OPTIONS"
	count(object.get(input.http.headers, "Access-Control-Request-Method", [])) > 0
	count(object.get(input.http.headers, "Origin", [])) > 0
}

# allow by email
allow {
	route := first_allowed_route(input.http.url)
	input.user.email = data.route_policies[route].allowed_users[_]
}

# allow group
allow {
	route := first_allowed_route(input.http.url)
    directory_groups := directory_user_data[input.user.id].Groups

	some group
	directory_groups[_] = group
	data.route_policies[route].allowed_groups[_] = group
}

# allow by impersonate email
allow {
	route := first_allowed_route(input.http.url)
	input.impersonate_email = data.route_policies[route].allowed_users[_]
}

# allow by impersonate group
allow {
	route := first_allowed_route(input.http.url)
	some group
	input.impersonate_groups[group] == data.route_policies[route].allowed_groups[_]
}

# allow by domain
allow {
	route := first_allowed_route(input.http.url)
	some domain
	email_in_domain(input.user.email, data.route_policies[route].allowed_domains[domain])
}

# allow by impersonate domain
allow {
	route := first_allowed_route(input.http.url)
	some domain
	email_in_domain(input.impersonate_email, data.route_policies[route].allowed_domains[domain])
}
# allow pomerium urls
allow {
	contains(input.http.url, "/.pomerium/")
	not contains(input.http.url,"/.pomerium/admin")
}

# allow user is admin
allow {
	element_in_list(data.admins, input.user.email)
	contains(input.http.url,".pomerium/admin")
}

# deny non-admin users from accesing admin routes
deny[reason] {
	reason = [403, "user is not admin"]
	not element_in_list(data.admins, input.user.email)
	contains(input.http.url,".pomerium/admin")
}

deny[reason] {
	reason = [495, "invalid client certificate"]
	is_boolean(input.is_valid_client_certificate)
	not input.is_valid_client_certificate
}

# returns the first matching route
first_allowed_route(input_url) = route {
	route := [route | some route ; allowed_route(input.http.url, data.route_policies[route])][0]
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

element_in_list(list, elem) {
  list[_] = elem
}
