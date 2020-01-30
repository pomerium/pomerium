package opa

//todo(bdd): embed source files directly, and setup tests.

const defaultAuthorization = `
package pomerium.authz
import data.route_policies
import data.shared_key

default allow = false

# allow by email
allow {
	some route
	input.host = route_policies[route].source
	jwt.payload.email = route_policies[route].allowed_users[_]
	jwt.valid
}

# allow group
allow {
	some route
	input.host = route_policies[route].source
	jwt.payload.groups[_] = route_policies[route].allowed_groups[_]
	jwt.valid
}

# allow by impersonate email
allow {
	some route
	input.host = route_policies[route].source
	jwt.payload.impersonate_email = route_policies[route].allowed_users[_]
	jwt.valid

}

# allow by impersonate group
allow {
	some route
	input.host = route_policies[route].source
	jwt.payload.impersonate_groups[_] = route_policies[route].allowed_groups[_]
	jwt.valid
}

# allow by domain 
allow {
	some route
	input.host = route_policies[route].source
	x := split(jwt.payload.email, "@")
	count(x)=2
	x[1] = route_policies[route].allowed_domains[_]
	jwt.valid
}

# allow by impersonate domain
allow {
	some route
	input.host = route_policies[route].source
	x := split(jwt.payload.impersonate_email, "@")
	count(x)=2
	x[1] == route_policies[route].allowed_domains[_]
	jwt.valid
}


jwt = {"payload": payload, "valid": valid} {
	[valid, header, payload] := io.jwt.decode_verify(
		input.user, {
			"secret": shared_key,
			"aud": input.host,
		}
	)
}
`

const defaultPAM = `
package pomerium.pam
import data.admins
import data.shared_key

default is_admin = false
is_admin{
	io.jwt.verify_hs256(input.user,shared_key)
	jwt.payload.email = admins[_]
}
jwt = {"payload": payload} {[header, payload, signature] := io.jwt.decode(input.user)}	
`
