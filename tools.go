//go:build tools
// +build tools

package pomerium

import (
	_ "github.com/client9/misspell/cmd/misspell"
	_ "github.com/envoyproxy/protoc-gen-validate"
	_ "github.com/golang/mock/mockgen"
	_ "github.com/golang/protobuf/protoc-gen-go"
)
