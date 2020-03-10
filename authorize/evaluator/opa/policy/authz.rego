package pomerium.authz

import data.route_policies
import data.shared_key

default allow = false

# allow by email
allow {
	some route
	input.host = route_policies[route].source
	token.payload.email = route_policies[route].allowed_users[_]
	token.valid
	count(deny)==0
}

# allow group
allow {
	some route
	input.host = route_policies[route].source
	token.payload.groups[_] = route_policies[route].allowed_groups[_]
	token.valid
	count(deny)==0
}

# allow by impersonate email
allow {
	some route
	input.host = route_policies[route].source
	token.payload.impersonate_email = route_policies[route].allowed_users[_]
	token.valid
	count(deny)==0
}

# allow by impersonate group
allow {
	some route
	input.host = route_policies[route].source
	token.payload.impersonate_groups[_] = route_policies[route].allowed_groups[_]
	token.valid
	count(deny)==0
}

# allow by domain 
allow {
	some route
	input.host = route_policies[route].source
	allowed_user_domain(token.payload.email)
	token.valid
	count(deny)==0
}

# allow by impersonate domain
allow {
	some route
	input.host = route_policies[route].source
	allowed_user_domain(token.payload.impersonate_email)
	token.valid
	count(deny)==0
}

allowed_user_domain(email){
	x := split(email, "@")
	count(x)=2
	x[1] == route_policies[route].allowed_domains[_]
}


default expired = false

expired {
	now_seconds:=time.now_ns()/1e9
	[header, payload, _] := io.jwt.decode(input.user)
	payload.exp < now_seconds
}

deny["token is expired (exp)"]{
	now_seconds:=time.now_ns()/1e9
	[header, payload, _] := io.jwt.decode(input.user)
	payload.exp < now_seconds
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