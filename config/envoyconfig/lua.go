package envoyconfig

import (
	"embed"
	"io/fs"
)

//go:embed luascripts
var luaFS embed.FS

var luascripts struct {
	CleanUpstream                string
	DropCheckRouteRequests       string
	ExtAuthzSetCookie            string
	RemoveImpersonateHeaders     string
	RewriteHeaders               string
	SetClientCertificateMetadata string
}

func init() {
	fileToField := map[string]*string{
		"luascripts/clean-upstream.lua":                  &luascripts.CleanUpstream,
		"luascripts/drop-check-route-requests.lua":       &luascripts.DropCheckRouteRequests,
		"luascripts/ext-authz-set-cookie.lua":            &luascripts.ExtAuthzSetCookie,
		"luascripts/remove-impersonate-headers.lua":      &luascripts.RemoveImpersonateHeaders,
		"luascripts/rewrite-headers.lua":                 &luascripts.RewriteHeaders,
		"luascripts/set-client-certificate-metadata.lua": &luascripts.SetClientCertificateMetadata,
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
