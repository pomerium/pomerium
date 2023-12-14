//go:build !embed_pomerium

package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed dist/*
var uiFS embed.FS

func openFile(name string) (f fs.File, etag string, err error) {
	f, err = os.Open(filepath.Join("ui", name))
	if os.IsNotExist(err) {
		f, err = uiFS.Open(name)
	}
	if err != nil {
		return nil, "", err
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, "", err
	}

	modTime := fi.ModTime()
	if modTime.IsZero() {
		modTime = startTime
	}
	etag = fmt.Sprintf("%x", modTime.UnixNano())

	return f, etag, nil
}
