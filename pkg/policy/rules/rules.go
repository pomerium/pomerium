// Package rules contains useful pre-defined rego AST rules.
package rules

import "github.com/open-policy-agent/opa/v1/ast"

// GetSession gets the session for the given id.
func GetSession() *ast.Rule {
	return MustParse(`
get_session(id) := v if {
	v = get_databroker_record("type.googleapis.com/user.ServiceAccount", id)
	v != null
} else := iv if {
	v = get_databroker_record("type.googleapis.com/session.Session", id)
	v != null
	object.get(v, "impersonate_session_id", "") != ""

	iv = get_databroker_record("type.googleapis.com/session.Session", v.impersonate_session_id)
	iv != null
} else := v if {
	v = get_databroker_record("type.googleapis.com/session.Session", id)
	v != null
	object.get(v, "impersonate_session_id", "") == ""
} else := {}
`)
}

// GetUser returns the user for the given session.
func GetUser() *ast.Rule {
	return MustParse(`
get_user(session) := v if {
	v = get_databroker_record("type.googleapis.com/user.User", session.user_id)
	v != null
} else := {}
`)
}

// GetUserEmail gets the user email, either the impersonate email, or the user email.
func GetUserEmail() *ast.Rule {
	return MustParse(`
get_user_email(session, user) := v if {
	v = user.email
} else := ""
`)
}

// GetDeviceCredential gets the device credential for the given session.
func GetDeviceCredential() *ast.Rule {
	return MustParse(`
get_device_credential(session, device_type_id) := v if {
	device_credential_id := [x.Credential.Id|x:=session.device_credentials[_];x.type_id==device_type_id][0]
	v = get_databroker_record("type.googleapis.com/pomerium.device.Credential", device_credential_id)
	v != null
} else := {}
`)
}

// GetDeviceEnrollment gets the device enrollment for the given device credential.
func GetDeviceEnrollment() *ast.Rule {
	return MustParse(`
get_device_enrollment(device_credential) := v if {
	v = get_databroker_record("type.googleapis.com/pomerium.device.Enrollment", device_credential.enrollment_id)
	v != null
} else := {}
`)
}

// MergeWithAnd merges criterion results using `and`.
func MergeWithAnd() *ast.Rule {
	return MustParse(`
merge_with_and(results) := [true, reasons, additional_data] if {
	true_results := [x|x:=results[i];x[0]]
	count(true_results) == count(results)
	reasons := union({x|x:=true_results[i][1]})
	additional_data := object_union({x|x:=true_results[i][2]})
} else := [false, reasons, additional_data] if {
	false_results := [x|x:=results[i];not x[0]]
	reasons := union({x|x:=false_results[i][1]})
	additional_data := object_union({x|x:=false_results[i][2]})
}
`)
}

// MergeWithOr merges criterion results using `or`.
func MergeWithOr() *ast.Rule {
	return MustParse(`
merge_with_or(results) := [true, reasons, additional_data] if {
	true_results := [x|x:=results[i];x[0]]
	count(true_results) > 0
	reasons := union({x|x:=true_results[i][1]})
	additional_data := object_union({x|x:=true_results[i][2]})
} else := [false, reasons, additional_data] if {
	false_results := [x|x:=results[i];not x[0]]
	reasons := union({x|x:=false_results[i][1]})
	additional_data := object_union({x|x:=false_results[i][2]})
}
`)
}

// InvertCriterionResult changes the criterion result's value from false to
// true, or vice-versa.
func InvertCriterionResult() *ast.Rule {
	return MustParse(`
invert_criterion_result(v) := out if {
	v[0]
	out = array.concat([false], array.slice(v, 1, count(v)))
} else := out if {
	not v[0]
	out = array.concat([true], array.slice(v, 1, count(v)))
}
`)
}

// NormalizeCriterionResult converts a criterion result into a standard form.
func NormalizeCriterionResult() *ast.Rule {
	return MustParse(`
normalize_criterion_result(result) := v if {
	is_boolean(result)
	v = [result, set()]
} else := v if {
	is_array(result)
	v = result
} else := v if {
	v = [false, set()]
}
`)
}

// ObjectGet recursively gets a value from an object.
func ObjectGet() *ast.Rule {
	return MustParse(`
# object_get is like object.get, but supports converting "/" in keys to separate lookups
# rego doesn't support recursion, so we hard code a limited number of /'s

object_get(obj, key, def) := value if {
	undefined := "10a0fd35-0f1a-4e5b-97ce-631e89e1bafa"
	value = object.get(obj, key, undefined)
	value != undefined
} else := value if {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 2
	o1 := object.get(obj, segments[0], {})
	value = object.get(o1, segments[1], def)
} else := value if {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 3
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	value = object.get(o2, segments[2], def)
} else := value if {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 4
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	value = object.get(o3, segments[3], def)
} else := value if {
	segments := split(replace(key, ".", "/"), "/")
	count(segments) == 5
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	o4 := object.get(o3, segments[3], {})
	value = object.get(o4, segments[4], def)
} else := value if {
	value = object.get(obj, key, def)
}
`)
}

// ObjectUnion merges objects together. It expects a set of objects.
func ObjectUnion() *ast.Rule {
	return MustParse(`
object_union(xs) := merged if {
	merged = { k: v |
		some k
		xs[_][k]
		vs := [ xv | xv := xs[_][k] ]
		v := vs[count(vs)-1]
	}
}
`)
}

// MustParse parses an AST rule.
func MustParse(str string) *ast.Rule {
	r, err := ast.ParseRuleWithOpts(str, ast.ParserOptions{
		RegoVersion: ast.RegoV1,
	})
	if err != nil {
		panic(err)
	}
	return r
}
