// Package opa implements the policy evaluator interface to make authorization
// decisions.
package opa

import _ "embed" // to embed files

//go:embed policy/headers.rego
// HeadersRego is the headers.rego script.
var HeadersRego string
