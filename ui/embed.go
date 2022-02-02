// Package ui contains the user info dashboard ui.
package ui

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	//go:embed dist/*
	uiFS embed.FS
)

// ServeJS serves the index.js file.
func ServeJS(w http.ResponseWriter, r *http.Request) error {
	f, etag, err := openLocalOrEmbeddedFile("dist/index.js")
	if err != nil {
		return err
	}
	defer f.Close()

	w.Header().Set("ETag", `"`+etag+`"`)
	http.ServeContent(w, r, "index.js", time.Time{}, f.(io.ReadSeeker))
	return nil
}

// ServeUserInfo serves the UserInfo page.
func ServeUserInfo(w http.ResponseWriter, r *http.Request, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	f, _, err := openLocalOrEmbeddedFile("dist/index.html")
	if err != nil {
		return err
	}
	bs, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return err
	}

	bs = bytes.Replace(bs,
		[]byte("window.POMERIUM_DATA = {}"),
		append([]byte("window.POMERIUM_DATA = "), jsonData...),
		1)

	http.ServeContent(w, r, "index.html", time.Now(), bytes.NewReader(bs))
	return nil
}

var startTime = time.Now()

func openLocalOrEmbeddedFile(name string) (f fs.File, etag string, err error) {
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
