// Package opa implements the policy evaluator interface to make authorization
// decisions.
package opa

import "embed"

// FS is the filesystem for OPA files.
//go:embed policy
var FS embed.FS
