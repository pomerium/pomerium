package controlplane

import (
	"os"

	"github.com/rakyll/statik/fs"

	// include luascripts source code
	_ "github.com/pomerium/pomerium/internal/controlplane/luascripts"
)

//go:generate go run github.com/rakyll/statik -src=./luascripts -include=*.lua -p luascripts -ns luascripts

var luascripts struct {
	ExtAuthzSetCookie string
	CleanUpstream     string
}

func init() {
	hfs, err := fs.NewWithNamespace("luascripts")
	if err != nil {
		panic(err)
	}

	fileToField := map[string]*string{
		"/clean-upstream.lua":       &luascripts.CleanUpstream,
		"/ext-authz-set-cookie.lua": &luascripts.ExtAuthzSetCookie,
	}

	err = fs.Walk(hfs, "/", func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if fi.IsDir() {
			return nil
		}

		bs, err := fs.ReadFile(hfs, p)
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
