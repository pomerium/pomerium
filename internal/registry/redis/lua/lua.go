// Package lua contains lua source code.
package lua

import (
	"embed"
)

//go:embed registry.lua
var fs embed.FS

// Registry is the registry lua script
var Registry string

func init() {
	bs, err := fs.ReadFile("registry.lua")
	if err != nil {
		panic(err)
	}
	Registry = string(bs)
}
