package pomerium.headers

import rego.v1

# input:
#   enable_google_cloud_serverless_authentication: boolean
#   enable_routing_key: boolean
#   client_certificate:
#     leaf: string
#   issuer: string
#   kubernetes_service_account_token: string
#   session:
#     id: string
#   to_audience: string
#   set_request_headers: map[string]string
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

now_s := round(time.now_ns() / 1e9)

# get the session
session := v if {
	# try a service account
	v = get_databroker_record("type.googleapis.com/user.ServiceAccount", input.session.id)
	v != null
} else := iv if {
	# try an impersonated session
	v = get_databroker_record("type.googleapis.com/session.Session", input.session.id)
	v != null
	object.get(v, "impersonate_session_id", "") != ""

	iv = get_databroker_record("type.googleapis.com/session.Session", v.impersonate_session_id)
	iv != null
} else := v if {
	# try a normal session
	v = get_databroker_record("type.googleapis.com/session.Session", input.session.id)
	v != null
	object.get(v, "impersonate_session_id", "") == ""
} else := {}

user := u if {
	u = get_databroker_record("type.googleapis.com/user.User", session.user_id)
	u != null
} else := {}

directory_user := du if {
	du = get_databroker_record("pomerium.io/DirectoryUser", session.user_id)
	du != null
} else := {}

group_ids := gs if {
	gs = directory_user.group_ids
	gs != null
} else := []

groups := array.concat(group_ids, array.concat(get_databroker_group_names(group_ids), get_databroker_group_emails(group_ids)))

jwt_headers := {
	"typ": "JWT",
	"alg": data.signing_key.alg,
	"kid": data.signing_key.kid,
}

jwt_payload_aud := v if {
	v := input.issuer
} else := ""

jwt_payload_iss := v if {
	v := input.issuer
} else := ""

jwt_payload_jti := uuid.rfc4122("jti")

jwt_payload_iat := now_s

jwt_payload_exp := now_s + (5*60) # 5 minutes from now

jwt_payload_sub := v if {
	v = session.user_id
} else := ""

jwt_payload_user := v if {
	v = session.user_id
} else := ""

jwt_payload_email := v if {
	v = directory_user.email
} else := v if {
	v = user.email
} else := ""

jwt_payload_groups := v if {
	v = array.concat(group_ids, get_databroker_group_names(group_ids))
	v != []
} else := v if {
	v = session.claims.groups
	v != null
} else := []

jwt_payload_name := v if {
	v = get_header_string_value(session.claims.name)
} else := v if {
	v = get_header_string_value(user.claims.name)
} else := ""

# the session id is always set to the input session id, even if impersonating
jwt_payload_sid := input.session.id

base_jwt_claims := [
	["iss", jwt_payload_iss],
	["aud", jwt_payload_aud],
	["jti", jwt_payload_jti],
	["iat", jwt_payload_iat],
	["exp", jwt_payload_exp],
	["sub", jwt_payload_sub],
	["user", jwt_payload_user],
	["email", jwt_payload_email],
	["groups", jwt_payload_groups],
	["sid", jwt_payload_sid],
	["name", jwt_payload_name],
]

session_claims := c if {
	c := session.claims
} else := {}

user_claims := c if {
	c := user.claims
} else := {}

additional_jwt_claims := [[k, v] |
	some header_name
	claim_key := data.jwt_claim_headers[header_name]

	# exclude base_jwt_claims
	count([1 |
		[xk, xv] := base_jwt_claims[_]
		xk == claim_key
	]) == 0

	# the claim value can come from session claims or user claims
	claim_value := object.get(session_claims, claim_key, object.get(user_claims, claim_key, null))

	k := claim_key
	v := get_header_string_value(claim_value)
]

jwt_claims := array.concat(base_jwt_claims, additional_jwt_claims)

jwt_payload := {key: value |
	# use a comprehension over an array to remove nil values
	[key, value] := jwt_claims[_]
	value != null
}

signed_jwt := io.jwt.encode_sign(jwt_headers, jwt_payload, data.signing_key)

impersonate_user_claim := u if {
	u := input.kubernetes_impersonate_user_claim
	u != ""
} else := "email"

impersonate_group_claim := g if {
	g := input.kubernetes_impersonate_group_claim
	g != ""
} else := "groups"

impersonate_user := v if {
	[k, v] := jwt_claims[_]
	k == impersonate_user_claim
}

impersonate_group := v if {
	[k, v] := jwt_claims[_]
	k == impersonate_group_claim
}

kubernetes_headers := h if {
	input.kubernetes_service_account_token != ""

	h := remove_empty_header_values([
		["Authorization", concat(" ", ["Bearer", input.kubernetes_service_account_token])],
		["Impersonate-User", impersonate_user],
		["Impersonate-Group", get_header_string_value(impersonate_group)],
	])
} else := []

google_cloud_serverless_authentication_service_account := s if {
	s := data.google_cloud_serverless_authentication_service_account
} else := ""

google_cloud_serverless_headers := h if {
	input.enable_google_cloud_serverless_authentication
	h := get_google_cloud_serverless_headers(google_cloud_serverless_authentication_service_account, input.to_audience)
} else := {}

routing_key_headers := h if {
	input.enable_routing_key
	h := [["x-pomerium-routing-key", crypto.sha256(input.session.id)]]
} else := []

session_id_token := v if {
	v := session.id_token.raw
} else := ""

session_access_token := v if {
	v := session.oauth_token.access_token
} else := ""

client_cert_fingerprint := v if {
	cert := crypto.x509.parse_certificates(trim_space(input.client_certificate.leaf))[0]
	v := crypto.sha256(base64.decode(cert.Raw))
} else := ""

set_request_headers := h if {
	replacements := {
		"pomerium.id_token": session_id_token,
		"pomerium.access_token": session_access_token,
		"pomerium.client_cert_fingerprint": client_cert_fingerprint,
	}
	h := [[header_name, header_value] |
		some header_name
		v := input.set_request_headers[header_name]
		header_value := pomerium.variable_substitution(v, replacements)
	]
} else := []

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
	h6 := set_request_headers

	h := array.concat(array.concat(array.concat(array.concat(array.concat(h1, h2), h3), h4), h5), h6)

	some i
	[key, v1] := h[i]
	values := [v2 |
		some j
		[k2, v2] := h[j]
		key == k2
	]
}

get_databroker_group_names(ids) := gs if {
	gs := [name | id := ids[i]; group := get_databroker_record("pomerium.io/DirectoryGroup", id); name := group.name]
}

get_databroker_group_emails(ids) := gs if {
	gs := [email | id := ids[i]; group := get_databroker_record("pomerium.io/DirectoryGroup", id); email := group.email]
}

get_header_string_value(obj) := s if {
	is_array(obj)
	s := concat(",", obj)
} else := s if {
	s := concat(",", [obj])
}

remove_empty_header_values(arr) := [[k, v] |
	some idx
	k := arr[idx][0]
	v := arr[idx][1]
	v != ""
]
