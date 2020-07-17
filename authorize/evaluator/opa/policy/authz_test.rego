package pomerium.authz

test_email_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_users": ["x@example.com"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com"
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_email": "" }
}

test_impersonate_email_not_allowed {
	not allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_users": ["x@example.com"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com"
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_email": "y@example.com" }
}

test_impersonate_email_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_users": ["y@example.com"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com"
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_email": "y@example.com" }
}

test_group_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_groups": ["1"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com",
			},
			"directory_user": {
			    "groups": ["1"]
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_groups": null }
}

test_impersonate_groups_not_allowed {
	not allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_groups": ["1"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com"
			},
			"directory_user": {
			    "groups": ["1"]
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_groups": ["2"] }
}

test_impersonate_groups_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_groups": ["2"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com"
			},
			"directory_user": {
			    "groups": ["1"]
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_groups": ["2"] }
}

test_domain_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_domains": ["example.com"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com"
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_email": "" }
}

test_impersonate_domain_not_allowed {
	not allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_domains": ["example.com"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com"
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_email": "y@example1.com" }
}

test_impersonate_domain_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_domains": ["example1.com"]
		}] with
		input.databroker_data as {
			"session": {
				"user_id": "user1"
			},
			"user": {
				"email": "x@example.com"
			}
		} with
		input.http as { "url": "http://example.com" } with
		input.session as { "id": "session1", "impersonate_email": "y@example1.com" }
}

test_example {
	not allow with
		data.route_policies as [
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
		] with
		input.http as { "url": "http://example.com/b" } with
		input.user as { "id": "1", "email": "joe@example.com" }
}

test_email_denied {
	not allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_users": ["bob@example.com"]
		}] with
		input.http as { "url": "http://example.com" } with
		input.user as { "id": "1", "email": "joe@example.com" }
}

test_public_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"AllowPublicUnauthenticatedAccess": true
		}] with
		input.http as { "url": "http://example.com" }
}
test_public_denied {
	not allow with
		data.route_policies as [
			{
				"source": "example.com",
				"prefix": "/by-user",
				"allowed_users": ["bob@example.com"]
			},
			{
				"source": "example.com",
				"AllowPublicUnauthenticatedAccess": true
			}
		] with
		input.http as {
			"url": "http://example.com/by-user"
		}
}

test_pomerium_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_users": ["bob@example.com"]
		}] with
		input.http as { "url": "http://example.com/.pomerium/" }
}
test_pomerium_denied {
	not allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_users": ["bob@example.com"]
		}] with
		input.http as {
			"url": "http://example.com/.pomerium/admin",
			"host": "example.com"
		}
}

test_cors_preflight_allowed {
	allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_users": ["bob@example.com"],
			"CORSAllowPreflight": true
		}] with
		input.http as {
			"method": "OPTIONS",
			"url": "http://example.com/",
			"headers": {
				"Origin": ["someorigin"],
				"Access-Control-Request-Method": ["GET"]
			}
		}
}
test_cors_preflight_denied {
	not allow with
		data.route_policies as [{
			"source": "example.com",
			"allowed_users": ["bob@example.com"]
		}] with
		input.http as {
			"method": "OPTIONS",
			"url": "http://example.com/",
			"headers": {
				"Origin": ["someorigin"],
				"Access-Control-Request-Method": ["GET"]
			}
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
