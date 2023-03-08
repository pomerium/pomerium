package pomerium.headers

# input:
#   enable_google_cloud_serverless_authentication: boolean
#   enable_routing_key: boolean
#   issuer: string
#   kubernetes_service_account_token: string
#   session:
#     id: string
#   to_audience: string
#   pass_access_token: boolean
#   pass_id_token: boolean
#
# data:
#   jwt_claim_headers: map[string]string
#   signing_key:
#     alg: string
#     kid: string
#
# functions:
#   get_databroker_record
#   get_google_cloud_serverless_headers
#
#
# output:
#   identity_headers: map[string][]string

# 5 minutes from now in seconds
five_minutes := round((time.now_ns() / 1e9) + (60 * 5))

# get the session
session = v {
	# try a service account
	v = get_databroker_record("type.googleapis.com/user.ServiceAccount", input.session.id)
	v != null
} else = iv {
	# try an impersonated session
	v = get_databroker_record("type.googleapis.com/session.Session", input.session.id)
	v != null
	object.get(v, "impersonate_session_id", "") != ""

	iv = get_databroker_record("type.googleapis.com/session.Session", v.impersonate_session_id)
	iv != null
} else = v {
	# try a normal session
	v = get_databroker_record("type.googleapis.com/session.Session", input.session.id)
	v != null
	object.get(v, "impersonate_session_id", "") == ""
} else = {} {
	true
}

user = u {
	u = get_databroker_record("type.googleapis.com/user.User", session.user_id)
	u != null
} else = {} {
	true
}

directory_user = du {
	du = get_databroker_record("pomerium.io/DirectoryUser", session.user_id)
	du != null
} else = {} {
	true
}

group_ids = gs {
	gs = directory_user.group_ids
	gs != null
} else = [] {
	true
}

groups := array.concat(group_ids, array.concat(get_databroker_group_names(group_ids), get_databroker_group_emails(group_ids)))

jwt_headers = {
	"typ": "JWT",
	"alg": data.signing_key.alg,
	"kid": data.signing_key.kid,
}

jwt_payload_aud = v {
	v := input.issuer
} else = "" {
	true
}

jwt_payload_iss = v {
	v := input.issuer
} else = "" {
	true
}

jwt_payload_jti = v {
	v = session.id
} else = "" {
	true
}

jwt_payload_exp = v {
	v = min([five_minutes, round(session.expires_at.seconds)])
} else = v {
	v = five_minutes
} else = null {
	true
}

jwt_payload_iat = v {
	# sessions store the issued_at on the id_token
	v = round(session.id_token.issued_at.seconds)
} else = v {
	# service accounts store the issued at directly
	v = round(session.issued_at.seconds)
} else = null {
	true
}

jwt_payload_sub = v {
	v = session.user_id
} else = "" {
	true
}

jwt_payload_user = v {
	v = session.user_id
} else = "" {
	true
}

jwt_payload_email = v {
	v = directory_user.email
} else = v {
	v = user.email
} else = "" {
	true
}

jwt_payload_groups = v {
	v = array.concat(group_ids, get_databroker_group_names(group_ids))
	v != []
} else = v {
	v = session.claims.groups
	v != null
} else = [] {
	true
}

jwt_payload_name = v {
	v = get_header_string_value(session.claims.name)
} else = v {
	v = get_header_string_value(user.claims.name)
} else = "" {
	true
}

# the session id is always set to the input session id, even if impersonating
jwt_payload_sid := input.session.id

base_jwt_claims := [
	["iss", jwt_payload_iss],
	["aud", jwt_payload_aud],
	["jti", jwt_payload_jti],
	["exp", jwt_payload_exp],
	["iat", jwt_payload_iat],
	["sub", jwt_payload_sub],
	["user", jwt_payload_user],
	["email", jwt_payload_email],
	["groups", jwt_payload_groups],
	["sid", jwt_payload_sid],
	["name", jwt_payload_name],
]

additional_jwt_claims := [[k, v] |
	some header_name
	claim_key := data.jwt_claim_headers[header_name]

	# exclude base_jwt_claims
	count([1 |
		[xk, xv] := base_jwt_claims[_]
		xk == claim_key
	]) == 0

	# the claim value can come from session claims or user claims
	claim_value := object.get(session.claims, claim_key, object.get(user.claims, claim_key, null))

	k := claim_key
	v := get_header_string_value(claim_value)
]

jwt_claims := array.concat(base_jwt_claims, additional_jwt_claims)

jwt_payload = {key: value |
	# use a comprehension over an array to remove nil values
	[key, value] := jwt_claims[_]
	value != null
}

signed_jwt = io.jwt.encode_sign(jwt_headers, jwt_payload, data.signing_key)

kubernetes_headers = h {
	input.kubernetes_service_account_token != ""
	h := [
		["Authorization", concat(" ", ["Bearer", input.kubernetes_service_account_token])],
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
	input.enable_google_cloud_serverless_authentication
	h := get_google_cloud_serverless_headers(google_cloud_serverless_authentication_service_account, input.to_audience)
} else = {} {
	true
}

routing_key_headers = h {
	input.enable_routing_key
	h := [["x-pomerium-routing-key", crypto.sha256(input.session.id)]]
} else = [] {
	true
}

pass_access_token_headers = h {
	input.pass_access_token
	h := [["Authorization", concat(" ", ["Bearer", session.oauth_token.access_token])]]
} else = [] {
	true
}

pass_id_token_headers = h {
	input.pass_id_token
	h := [["Authorization", concat(" ", ["Bearer", session.id_token.raw])]]
} else = [] {
	true
}

identity_headers := {key: values |
	h1 := [["x-pomerium-jwt-assertion", signed_jwt]]
	h2 := [[header_name, header_value] |
		some header_name
		k := data.jwt_claim_headers[header_name]
		raw_header_value := array.concat(
			[cv |
				[ck, cv] := jwt_claims[_]
				ck == k
			],
			[""],
		)[0]

		header_value := get_header_string_value(raw_header_value)
	]

	h3 := kubernetes_headers
	h4 := [[k, v] | v := google_cloud_serverless_headers[k]]
	h5 := routing_key_headers
	h6 := pass_access_token_headers
	h7 := pass_id_token_headers

	h := array.concat(array.concat(array.concat(array.concat(array.concat(array.concat(h1, h2), h3), h4), h5), h6), h7)

	some i
	[key, v1] := h[i]
	values := [v2 |
		some j
		[k2, v2] := h[j]
		key == k2
	]
}

get_databroker_group_names(ids) = gs {
	gs := [name | id := ids[i]; group := get_databroker_record("pomerium.io/DirectoryGroup", id); name := group.name]
}

get_databroker_group_emails(ids) = gs {
	gs := [email | id := ids[i]; group := get_databroker_record("pomerium.io/DirectoryGroup", id); email := group.email]
}

get_header_string_value(obj) = s {
	is_array(obj)
	s := concat(",", obj)
} else = s {
	s := concat(",", [obj])
}
