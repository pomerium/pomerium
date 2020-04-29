package pomerium.authz

jwt_header := {
	"typ": "JWT",
	"alg": "HS256"
}
signing_key := {
	"kty": "oct",
	"k": "OkFmqMK9U0dmPhMCW0VYy6D_raJKwEJsMdxqdnukThzko3D_XrsihwYE0pxrUSpm0JTrW2QpIz4rT1vdEvZw67WP4xrqjiwyd7PgpPTD5xvQBM7TIKiSW0X2R0pfq_OItszPQRtb7VirrSbGJiLNS-NJMMrYVKWWtUbVSTXEjL7VcFqML5PiSe7XDmyCZjpgEpfE5Q82zIeXM2sLrz6HW2A9IwGk7mWS0c57R_2JGyFO2tCA4zEIYhWvLE62Os2tZ6YrrwdB8n35jlPpgUE6poEvIU20lPLaocozXYMqAku-KJnloJlAzKg2Xa_0iSiSgSAumx44B3n7DQjg3jPhRg"
}
shared_key := base64url.decode(signing_key.k)

test_email_allowed {
	user := io.jwt.encode_sign(jwt_header, {
		"aud": ["example.com"],
		"email": "joe@example.com"
	}, signing_key)

	allow with data.route_policies as [{
		"source": "example.com",
		"allowed_users": ["joe@example.com"]
	}] with data.signing_key as signing_key with data.shared_key as shared_key with input as {
		"url": "http://example.com",
		"host": "example.com",
		"user": user
	}
}

test_example {
	user := io.jwt.encode_sign(jwt_header, {
		"aud": ["example.com"],
		"email": "joe@example.com"
	}, signing_key)
	not allow with data.route_policies as [
		{
			"source": "http://example.com",
			"path": "/a",
			"allowed_domains": ["example.com"]
		},
		{
			"source": "http://example.com",
			"path": "/b",
			"allowed_users": ["noone@pomerium.com"]
		},
	] with data.signing_key as signing_key with data.shared_key as shared_key with input as {
		"url": "http://example.com/b",
		"host": "example.com",
		"user": user
	}
}

test_email_denied {
	user := io.jwt.encode_sign(jwt_header, {
		"aud": ["example.com"],
		"email": "joe@example.com"
	}, signing_key)

	not allow with data.route_policies as [{
		"source": "example.com",
		"allowed_users": ["bob@example.com"]
	}] with data.signing_key as signing_key with data.shared_key as shared_key with input as {
		"url": "http://example.com",
		"host": "example.com",
		"user": user
	}
}

test_public_allowed {
	allow with data.route_policies as [{
		"source": "example.com",
		"AllowPublicUnauthenticatedAccess": true
	}] with input as {
		"url": "http://example.com",
		"host": "example.com"
	}
}
test_public_denied {
	not allow with data.route_policies as [
		{
			"source": "example.com",
			"prefix": "/by-user",
			"allowed_users": ["bob@example.com"]
		},
		{
			"source": "example.com",
			"AllowPublicUnauthenticatedAccess": true
		}
	] with input as {
		"url": "http://example.com/by-user",
		"host": "example.com"
	}
}

test_pomerium_allowed {
	allow with data.route_policies as [{
		"source": "example.com",
		"allowed_users": ["bob@example.com"]
	}] with input as {
		"url": "http://example.com/.pomerium/",
		"host": "example.com"
	}
}
test_pomerium_denied {
	not allow with data.route_policies as [{
		"source": "example.com",
		"allowed_users": ["bob@example.com"]
	}] with input as {
		"url": "http://example.com/.pomerium/admin",
		"host": "example.com"
	}
}

test_parse_url {
	url := parse_url("http://example.com/some/path?qs")
	url.scheme == "http"
	url.host == "example.com"
	url.path == "/some/path"
}

test_allowed_route_source {
	allowed_route("http://example.com", {"source": "example.com"})
	allowed_route("http://example.com", {"source": "http://example.com"})
	allowed_route("http://example.com", {"source": "https://example.com"})
	allowed_route("http://example.com/", {"source": "https://example.com"})
	allowed_route("http://example.com", {"source": "https://example.com/"})
	allowed_route("http://example.com/", {"source": "https://example.com/"})
	not allowed_route("http://example.org", {"source": "example.com"})
}

test_allowed_route_prefix {
	allowed_route("http://example.com", {"prefix": "/"})
	allowed_route("http://example.com/admin/somepath", {"prefix": "/admin"})
	not allowed_route("http://example.com", {"prefix": "/admin"})
}

test_allowed_route_path {
	allowed_route("http://example.com", {"path": "/"})
	allowed_route("http://example.com/", {"path": "/"})
	not allowed_route("http://example.com/admin/somepath", {"path": "/admin"})
	not allowed_route("http://example.com", {"path": "/admin"})
}

test_allowed_route_regex {
	allowed_route("http://example.com", {"regex": ".*"})
	allowed_route("http://example.com/admin/somepath", {"regex": "/admin/.*"})
	not allowed_route("http://example.com", {"regex": "[xyz]"})
}
