// Package opa implements the policy evaluator interface to make authorization
// decisions.
package opa

import _ "embed" // to embed files

// HeadersRego is the headers.rego script.
//go:embed policy/headers.rego
var HeadersRego string
