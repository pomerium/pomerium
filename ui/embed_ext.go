//go:build embed_pomerium

package ui

import (
	"fmt"
	"io/fs"
)

// ExtUIFS must be set to provide access to UI dist/ files
var ExtUIFS fs.FS

func openFile(name string) (f fs.File, etag string, err error) {
	if ExtUIFS == nil {
		return nil, "", fmt.Errorf("ui package was incorrectly compiled with embed_pomerium yet no FS was provided")
	}
	f, err = ExtUIFS.Open(name)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", name, err)
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
