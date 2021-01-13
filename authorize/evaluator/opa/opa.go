// Package opa implements the policy evaluator interface to make authorization
// decisions.
package opa

//go:generate go run github.com/rakyll/statik -m -src=./policy -include=*.rego -ns rego -p policy
//go:generate go fmt ./policy/statik.go
