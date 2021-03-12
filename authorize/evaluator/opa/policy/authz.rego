package pomerium.authz

default allow = false

# 5 minutes from now in seconds
five_minutes := (time.now_ns() / 1e9) + (60 * 5)

route_policy_idx := first_allowed_route_policy_idx(input.http.url)

route_policy := data.route_policies[route_policy_idx]

session = s {
	s = object_get(data.databroker_data["type.googleapis.com"]["user.ServiceAccount"], input.session.id, null)
	s != null
} else = s {
	s = object_get(data.databroker_data["type.googleapis.com"]["session.Session"], input.session.id, null)
	s != null
} else = {} {
	true
}

user = u {
	u = object_get(data.databroker_data["type.googleapis.com"]["user.User"], session.impersonate_user_id, null)
	u != null
} else = u {
	u = object_get(data.databroker_data["type.googleapis.com"]["user.User"], session.user_id, null)
	u != null
} else = {} {
	true
}

directory_user = du {
	du = object_get(data.databroker_data["type.googleapis.com"]["directory.User"], session.impersonate_user_id, null)
	du != null
} else = du {
	du = object_get(data.databroker_data["type.googleapis.com"]["directory.User"], session.user_id, null)
	du != null
} else = {} {
	true
}

group_ids = gs {
	gs = session.impersonate_groups
	gs != null
} else = gs {
	gs = directory_user.group_ids
	gs != null
} else = [] {
	true
}

groups := array.concat(group_ids, array.concat(get_databroker_group_names(group_ids), get_databroker_group_emails(group_ids)))

all_allowed_domains := get_allowed_domains(route_policy)

all_allowed_groups := get_allowed_groups(route_policy)

all_allowed_users := get_allowed_users(route_policy)

all_allowed_idp_claims := get_allowed_idp_claims(route_policy)

is_impersonating := count(session.impersonate_email) > 0

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

# allow by user email
allow {
	not is_impersonating
	user.email == all_allowed_users[_]
}

# allow by user id
allow {
	not is_impersonating
	user.id == all_allowed_users[_]
}

# allow group
allow {
	not is_impersonating
	some group
	groups[_] = group
	all_allowed_groups[_] = group
}

# allow by impersonate email
allow {
	is_impersonating
	all_allowed_users[_] = session.impersonate_email
}

# allow by impersonate group
allow {
	is_impersonating
	some group
	session.impersonate_groups[_] = group
	all_allowed_groups[_] = group
}

# allow by domain
allow {
	not is_impersonating
	some domain
	email_in_domain(user.email, all_allowed_domains[domain])
}

# allow by impersonate domain
allow {
	is_impersonating
	some domain
	email_in_domain(session.impersonate_email, all_allowed_domains[domain])
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
}

deny[reason] {
	reason = [495, "invalid client certificate"]
	is_boolean(input.is_valid_client_certificate)
	not input.is_valid_client_certificate
}

jwt_headers = {
	"typ": "JWT",
	"alg": data.signing_key.alg,
	"kid": data.signing_key.kid,
}

jwt_payload_aud = v {
	v = parse_url(input.http.url).hostname
} else = "" {
	true
}

jwt_payload_iss = data.issuer

jwt_payload_jti = v {
	v = session.id
} else = "" {
	true
}

jwt_payload_exp = v {
	v = min([five_minutes, session.expires_at.seconds])
} else = v {
	v = five_minutes
} else = null {
	true
}

jwt_payload_iat = v {
	# sessions store the issued_at on the id_token
	v = session.id_token.issued_at.seconds
} else = v {
	# service accounts store the issued at directly
	v = session.issued_at.seconds
} else = null {
	true
}

jwt_payload_sub = v {
	v = user.id
} else = "" {
	true
}

jwt_payload_user = v {
	v = user.id
} else = "" {
	true
}

jwt_payload_email = v {
	v = session.impersonate_email
} else = v {
	v = directory_user.email
} else = v {
	v = user.email
} else = "" {
	true
}

jwt_payload_groups = v {
	v = array.concat(group_ids, get_databroker_group_names(group_ids))
} else = [] {
	true
}

jwt_claims := [
	["iss", jwt_payload_iss],
	["aud", jwt_payload_aud],
	["jti", jwt_payload_jti],
	["exp", jwt_payload_exp],
	["iat", jwt_payload_iat],
	["sub", jwt_payload_sub],
	["user", jwt_payload_user],
	["email", jwt_payload_email],
	["groups", jwt_payload_groups],
]

jwt_payload = {key: value |
	# use a comprehension over an array to remove nil values
	[key, value] := jwt_claims[_]
	value != null
}

signed_jwt = io.jwt.encode_sign(jwt_headers, jwt_payload, data.signing_key)

kubernetes_headers = h {
	route_policy.KubernetesServiceAccountToken != ""
	h := [
		["Authorization", concat(" ", ["Bearer", route_policy.KubernetesServiceAccountToken])],
		["Impersonate-User", jwt_payload_email],
		["Impersonate-Group", get_header_string_value(jwt_payload_groups)],
	]
} else = [] {
	true
}

google_cloud_serverless_authentication_service_account = s {
	s := data.google_cloud_serverless_authentication_service_account
} else = "" {
	true
}

google_cloud_serverless_headers = h {
	route_policy.EnableGoogleCloudServerlessAuthentication
	[hostname, _] := parse_host_port(route_policy.To[0].URL.Host)
	audience := concat("", ["https://", hostname])
	h := get_google_cloud_serverless_headers(google_cloud_serverless_authentication_service_account, audience)
} else = {} {
	true
}

identity_headers := {key: value |
	h1 := [["x-pomerium-jwt-assertion", signed_jwt]]
	h2 := [[k, v] |
		[claim_key, claim_value] := jwt_claims[_]
		claim_value != null

		# only include those headers requested by the user
		some header_name
		available := data.jwt_claim_headers[header_name]
		available == claim_key

		# create the header key and value
		k := header_name
		v := get_header_string_value(claim_value)
	]

	h3 := kubernetes_headers
	h4 := [[k, v] | v := google_cloud_serverless_headers[k]]

	h := array.concat(array.concat(array.concat(h1, h2), h3), h4)
	[key, value] := h[_]
}

# returns the first matching route
first_allowed_route_policy_idx(input_url) = first_policy_idx {
	first_policy_idx := [idx | some idx, policy; policy = data.route_policies[idx]; allowed_route(input.http.url, policy)][0]
}

allowed_route(input_url, policy) {
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

parse_url(str) = {"scheme": scheme, "host": host, "hostname": hostname, "path": path} {
	[_, scheme, host, rawpath] = regex.find_all_string_submatch_n(`(?:((?:tcp[+])?http[s]?)://)?([^/]+)([^?#]*)`, str, 1)[0]
	[hostname, _] = parse_host_port(host)
	path = normalize_url_path(rawpath)
}

parse_host_port(str) = [host, port] {
	contains(str, ":")
	[host, port] = split(str, ":")
} else = [host, port] {
	host = str
	port = "443"
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
	v := {x | x = array.concat(policy.allowed_users, [u | u := policy.sub_policies[_].allowed_users[_]])[_]}
}

get_allowed_domains(policy) = v {
	v := {x | x = array.concat(policy.allowed_domains, [u | u := policy.sub_policies[_].allowed_domains[_]])[_]}
}

get_allowed_groups(policy) = v {
	v := {x | x = array.concat(policy.allowed_groups, [u | u := policy.sub_policies[_].allowed_groups[_]])[_]}
}

get_allowed_idp_claims(policy) = v {
	v := array.concat([policy.allowed_idp_claims], [u | u := policy.sub_policies[_].allowed_idp_claims])
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

get_databroker_group_names(ids) = gs {
	gs := [name | id := ids[i]; group := data.databroker_data["type.googleapis.com"]["directory.Group"][id]; name := group.name]
}

get_databroker_group_emails(ids) = gs {
	gs := [email | id := ids[i]; group := data.databroker_data["type.googleapis.com"]["directory.Group"][id]; email := group.email]
}

get_header_string_value(obj) = s {
	is_array(obj)
	s := concat(",", obj)
} else = s {
	s := concat(",", [obj])
}

# object_get is like object.get, but supports converting "/" in keys to separate lookups
# rego doesn't support recursion, so we hard code a limited number of /'s
object_get(obj, key, def) = value {
	segments := split(key, "/")
	count(segments) == 2
	o1 := object.get(obj, segments[0], {})
	value = object.get(o1, segments[1], def)
} else = value {
	segments := split(key, "/")
	count(segments) == 3
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	value = object.get(o2, segments[2], def)
} else = value {
	segments := split(key, "/")
	count(segments) == 4
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	value = object.get(o3, segments[3], def)
} else = value {
	segments := split(key, "/")
	count(segments) == 5
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	o4 := object.get(o3, segments[3], {})
	value = object.get(o4, segments[4], def)
} else = value {
	value = object.get(obj, key, def)
}
