package envoyconfig

import (
	"embed"
	"io/fs"
)

//go:embed luascripts
var luaFS embed.FS

var luascripts struct {
	ExtAuthzSetCookie        string
	CleanUpstream            string
	RemoveImpersonateHeaders string
	RewriteHeaders           string
	FixMisdirected           string
}

func init() {
	fileToField := map[string]*string{
		"luascripts/clean-upstream.lua":             &luascripts.CleanUpstream,
		"luascripts/ext-authz-set-cookie.lua":       &luascripts.ExtAuthzSetCookie,
		"luascripts/remove-impersonate-headers.lua": &luascripts.RemoveImpersonateHeaders,
		"luascripts/rewrite-headers.lua":            &luascripts.RewriteHeaders,
		"luascripts/fix-misdirected.lua":            &luascripts.FixMisdirected,
	}

	err := fs.WalkDir(luaFS, "luascripts", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		bs, err := luaFS.ReadFile(p)
		if err != nil {
			return err
		}

		if ptr, ok := fileToField[p]; ok {
			*ptr = string(bs)
		}

		return nil
	})
	if err != nil {
		panic(err)
	}
}
