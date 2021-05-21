// Package rules contains useful pre-defined rego AST rules.
package rules

import "github.com/open-policy-agent/opa/ast"

// GetSession the session for the given id.
func GetSession() *ast.Rule {
	return ast.MustParseRule(`
get_session(id) = v {
	v = get_databroker_record("type.googleapis.com/user.ServiceAccount", id)
	v != null
} else = v {
	v = get_databroker_record("type.googleapis.com/session.Session", id)
	v != null
} else = {} {
	true
}
`)
}

// GetUser returns the user for the given session.
func GetUser() *ast.Rule {
	return ast.MustParseRule(`
get_user(session) = v {
	v = get_databroker_record("type.googleapis.com/user.User", session.impersonate_user_id)
	v != null
} else = v {
	v = get_databroker_record("type.googleapis.com/user.User", session.user_id)
	v != null
} else = {} {
	true
}
`)
}

// GetUserEmail gets the user email, either the impersonate email, or the user email.
func GetUserEmail() *ast.Rule {
	return ast.MustParseRule(`
get_user_email(session, user) = v {
	v = session.impersonate_email
} else = v {
	v = user.email
} else = "" {
	true
}
`)
}

// GetDirectoryUser returns the directory user for the given session.
func GetDirectoryUser() *ast.Rule {
	return ast.MustParseRule(`
get_directory_user(session) = v {
	v = get_databroker_record("type.googleapis.com/directory.User", session.impersonate_user_id)
	v != null
} else = v {
	v = get_databroker_record("type.googleapis.com/directory.User", session.user_id)
	v != null
} else = "" {
	true
}
`)
}

// GetDirectoryGroup returns the directory group for the given id.
func GetDirectoryGroup() *ast.Rule {
	return ast.MustParseRule(`
get_directory_group(id) = v {
	v = get_databroker_record("type.googleapis.com/directory.Group", id)
	v != null
} else = {} {
	true
}
`)
}

// GetGroupIDs returns the group ids for the given session or directory user.
func GetGroupIDs() *ast.Rule {
	return ast.MustParseRule(`
get_group_ids(session, directory_user) = v {
	v = session.impersonate_groups
	v != null
} else = v {
	v = directory_user.group_ids
	v != null
} else = [] {
	true
}
`)
}

// ObjectGet recursively gets a value from an object.
func ObjectGet() *ast.Rule {
	return ast.MustParseRule(`
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
`)
}
